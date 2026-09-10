// Copyright 2023 Harness, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package netpolicy classifies network addresses and restricts which of them
// outbound requests to user provided destinations are allowed to reach.
//
// It exists to keep a single, shared definition of "internal address" for every
// component that dials a host controlled by an end user (webhooks, repository
// import, ...). Duplicating the range list per component is how gaps appear.
package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"syscall"
)

// ErrAddressNotAllowed is returned for every address rejected by a Policy.
// It is deliberately uniform. An error that reveals why an address
// was rejected, or that differs from the error of an unreachable address, turns
// the dialer into an oracle for internal network state.
var ErrAddressNotAllowed = errors.New("network address is not allowed")

// Class describes the reachability class of an IP address.
type Class int

const (
	// ClassPublic is a globally routable unicast address.
	ClassPublic Class = iota

	// ClassLoopback is 127.0.0.0/8 or ::1/128.
	ClassLoopback

	// ClassLinkLocal is link-local unicast (169.254.0.0/16, fe80::/10), which
	// includes the ranges commonly used for cloud instance metadata services.
	ClassLinkLocal

	// ClassPrivate is RFC 1918 (10/8, 172.16/12, 192.168/16) or RFC 4193 (fc00::/7).
	ClassPrivate

	// ClassReserved is anything else that must not be dialed: the unspecified
	// address, multicast, broadcast, carrier-grade NAT, documentation and
	// benchmarking ranges, and the transition ranges (6to4, Teredo, NAT64)
	// which can embed an otherwise blocked IPv4 address.
	ClassReserved
)

// String returns a lower case, human-readable name of the class.
func (c Class) String() string {
	switch c {
	case ClassPublic:
		return "public"
	case ClassLoopback:
		return "loopback"
	case ClassLinkLocal:
		return "link-local"
	case ClassPrivate:
		return "private"
	case ClassReserved:
		return "reserved"
	default:
		return fmt.Sprintf("unknown(%d)", int(c))
	}
}

// reservedPrefixes lists the ranges that must never be dialed and for which the
// standard library has no predicate. The transition ranges are included because
// they can encode an internal IPv4 destination inside an IPv6 address.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" (RFC 1122)
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments (RFC 6890)
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1 (RFC 5737)
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast (RFC 7526)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2 (RFC 5737)
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3 (RFC 5737)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. broadcast (RFC 1112)
	netip.MustParsePrefix("100::/64"),        // discard-only (RFC 6666)
	netip.MustParsePrefix("2001::/32"),       // Teredo (RFC 4380)
	netip.MustParsePrefix("2001:db8::/32"),   // documentation (RFC 3849)
	netip.MustParsePrefix("2002::/16"),       // 6to4 (RFC 3056)
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 well-known prefix (RFC 6052)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64 (RFC 8215)
}

// Classify returns the reachability class of ip.
// An invalid address is classified as ClassReserved.
func Classify(ip net.IP) Class {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ClassReserved
	}

	return ClassifyAddr(addr)
}

// ClassifyAddr returns the reachability class of addr.
// An invalid address is classified as ClassReserved.
func ClassifyAddr(addr netip.Addr) Class {
	if !addr.IsValid() {
		return ClassReserved
	}

	// IMPORTANT: unmap first - without this, ::ffff:169.254.169.254 is neither
	// recognized as link-local nor matched by any IPv4 prefix below.
	addr = addr.Unmap()

	switch {
	// NOTE: multicast is classified before link-local on purpose. Link-local
	// multicast (224.0.0.0/24, ff02::/16) is never a valid unicast destination,
	// so it must not become reachable by allowing link-local addresses.
	case addr.IsUnspecified(), addr.IsMulticast(), addr.IsInterfaceLocalMulticast():
		return ClassReserved
	case addr.IsLoopback():
		return ClassLoopback
	case addr.IsLinkLocalUnicast():
		return ClassLinkLocal
	case addr.IsPrivate():
		return ClassPrivate
	}

	for _, prefix := range reservedPrefixes {
		if prefix.Contains(addr) {
			return ClassReserved
		}
	}

	if !addr.IsGlobalUnicast() {
		return ClassReserved
	}

	return ClassPublic
}

// Policy defines which classes of addresses may be dialed. The zero value
// allows public addresses only, which is the safe default for any destination
// that originates from user input.
type Policy struct {
	AllowLoopback       bool
	AllowPrivateNetwork bool
	AllowLinkLocal      bool
}

// Allows reports whether addresses of the given class may be dialed.
func (p Policy) Allows(c Class) bool {
	switch c {
	case ClassPublic:
		return true
	case ClassLoopback:
		return p.AllowLoopback
	case ClassLinkLocal:
		return p.AllowLinkLocal
	case ClassPrivate:
		return p.AllowPrivateNetwork
	case ClassReserved:
		return false
	default:
		return false
	}
}

// AllowsAddr reports whether addr may be dialed.
func (p Policy) AllowsAddr(addr netip.Addr) bool {
	return p.Allows(ClassifyAddr(addr))
}

// ControlFunc returns a function for net.Dialer.Control that rejects any
// address not allowed by p.
//
// Control runs after the destination has been resolved but before the connect
// syscall, which is what makes it the right hook for this check:
//   - a rejected address is never contacted, so neither a successful handshake
//     nor a connection error can be used to probe internal network state, and
//   - it is invoked for every address the dialer actually attempts, so a DNS
//     answer cannot be swapped for an internal address after validation.
//
// errFn maps the class of a rejected address to the returned error, allowing
// the caller to decide how much detail is exposed. If errFn is nil (or returns
// nil) ErrAddressNotAllowed is returned for every rejected address; prefer that
// for destinations reachable by any authenticated user.
func (p Policy) ControlFunc(errFn func(Class) error) func(network, address string, c syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrAddressNotAllowed
		}

		// Control is called with an already resolved address, so this parses
		// rather than resolves - a name reaching this point is unexpected.
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return ErrAddressNotAllowed
		}

		class := ClassifyAddr(addr)
		if p.Allows(class) {
			return nil
		}

		if errFn != nil {
			if classErr := errFn(class); classErr != nil {
				return classErr
			}
		}

		return ErrAddressNotAllowed
	}
}

// Resolver resolves host names to IP addresses. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// CheckHost resolves host and returns ErrAddressNotAllowed unless every
// resolved address is allowed by p. A host that is already an IP literal is
// checked without a lookup. Resolution failures are returned as-is.
//
// NOTE: prefer ControlFunc wherever the connection is dialed by this process.
// CheckHost resolves the name itself, so the address may in principle change
// between the check and the connection; it is meant for destinations handed to
// an external process (e.g. a git clone) where no dial hook is available.
func (p Policy) CheckHost(ctx context.Context, resolver Resolver, host string) error {
	if host == "" {
		return ErrAddressNotAllowed
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if !p.AllowsAddr(addr) {
			return ErrAddressNotAllowed
		}
		return nil
	}

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("failed to resolve host: %w", err)
	}

	if len(addrs) == 0 {
		return ErrAddressNotAllowed
	}

	for _, addr := range addrs {
		if !p.AllowsAddr(addr) {
			return ErrAddressNotAllowed
		}
	}

	return nil
}

// CheckURLHost resolves the host of rawURL and verifies it against p.
// The URL must use the http or https scheme.
func (p Policy) CheckURLHost(ctx context.Context, resolver Resolver, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("failed to parse url: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ErrAddressNotAllowed
	}

	return p.CheckHost(ctx, resolver, parsed.Hostname())
}
