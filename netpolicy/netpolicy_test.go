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

package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		addr string
		want Class
	}{
		// the address from the SSRF report and the cloud metadata endpoints.
		{"169.254.169.252", ClassLinkLocal},
		{"169.254.169.254", ClassLinkLocal},
		{"fe80::1", ClassLinkLocal},
		// link-local multicast is not a unicast destination - reserved, so that
		// allowing link-local addresses does not make it reachable.
		{"ff02::1", ClassReserved},
		{"224.0.0.1", ClassReserved},
		// IPv4-mapped IPv6 must not bypass the IPv4 classification.
		{"::ffff:169.254.169.254", ClassLinkLocal},
		{"::ffff:127.0.0.1", ClassLoopback},
		{"::ffff:10.0.0.1", ClassPrivate},

		{"127.0.0.1", ClassLoopback},
		{"127.1.2.3", ClassLoopback},
		{"::1", ClassLoopback},

		{"10.0.0.1", ClassPrivate},
		{"172.16.0.1", ClassPrivate},
		{"192.168.1.1", ClassPrivate},
		{"fc00::1", ClassPrivate},
		{"fd12:3456::1", ClassPrivate},

		{"0.0.0.0", ClassReserved},
		{"0.1.2.3", ClassReserved},
		{"::", ClassReserved},
		{"100.64.0.1", ClassReserved},
		{"192.0.0.1", ClassReserved},
		{"192.0.2.1", ClassReserved},
		{"192.88.99.1", ClassReserved},
		{"198.18.0.1", ClassReserved},
		{"198.51.100.1", ClassReserved},
		{"203.0.113.1", ClassReserved},
		{"240.0.0.1", ClassReserved},
		{"255.255.255.255", ClassReserved},
		{"ff01::1", ClassReserved},
		{"100::1", ClassReserved},
		{"2001::1", ClassReserved},
		{"2001:db8::1", ClassReserved},
		// 6to4 and NAT64 can encode an internal IPv4 destination.
		{"2002:a9fe:a9fe::1", ClassReserved},
		{"64:ff9b::a9fe:a9fe", ClassReserved},
		{"64:ff9b:1::1", ClassReserved},

		{"1.1.1.1", ClassPublic},
		{"140.82.121.4", ClassPublic},
		{"2606:4700::1", ClassPublic},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.addr)
			if err != nil {
				t.Fatalf("failed to parse %q: %v", tt.addr, err)
			}

			if got := ClassifyAddr(addr); got != tt.want {
				t.Errorf("ClassifyAddr(%q) = %v, want %v", tt.addr, got, tt.want)
			}

			// net.IP based classification must agree.
			if got := Classify(net.ParseIP(tt.addr)); got != tt.want {
				t.Errorf("Classify(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestClassifyInvalid(t *testing.T) {
	if got := ClassifyAddr(netip.Addr{}); got != ClassReserved {
		t.Errorf("ClassifyAddr(invalid) = %v, want %v", got, ClassReserved)
	}
	if got := Classify(nil); got != ClassReserved {
		t.Errorf("Classify(nil) = %v, want %v", got, ClassReserved)
	}
	if got := Classify(net.IP{1, 2, 3}); got != ClassReserved {
		t.Errorf("Classify(malformed) = %v, want %v", got, ClassReserved)
	}
}

func TestPolicyAllows(t *testing.T) {
	deny := Policy{}
	for _, class := range []Class{ClassLoopback, ClassLinkLocal, ClassPrivate, ClassReserved} {
		if deny.Allows(class) {
			t.Errorf("zero value Policy must not allow %v", class)
		}
	}
	if !deny.Allows(ClassPublic) {
		t.Error("zero value Policy must allow public addresses")
	}

	allowAll := Policy{AllowLoopback: true, AllowPrivateNetwork: true, AllowLinkLocal: true}
	for _, class := range []Class{ClassPublic, ClassLoopback, ClassLinkLocal, ClassPrivate} {
		if !allowAll.Allows(class) {
			t.Errorf("permissive Policy must allow %v", class)
		}
	}
	if allowAll.Allows(ClassReserved) {
		t.Error("reserved addresses must never be allowed")
	}
}

func TestControlFunc(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		address string
		wantErr bool
	}{
		{name: "link-local blocked", address: "169.254.169.252:988", wantErr: true},
		{name: "loopback blocked", address: "127.0.0.1:80", wantErr: true},
		{name: "private blocked", address: "10.1.2.3:80", wantErr: true},
		{name: "reserved blocked", address: "100.64.1.2:80", wantErr: true},
		{name: "public allowed", address: "1.1.1.1:443", wantErr: false},
		{
			name:    "link-local allowed by policy",
			policy:  Policy{AllowLinkLocal: true},
			address: "169.254.169.252:988",
			wantErr: false,
		},
		{
			name:    "loopback allowed by policy",
			policy:  Policy{AllowLoopback: true},
			address: "127.0.0.1:80",
			wantErr: false,
		},
		{name: "unresolved name blocked", address: "example.com:80", wantErr: true},
		{name: "malformed address blocked", address: "not-an-address", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.ControlFunc(nil)("tcp", tt.address, nil)
			if tt.wantErr {
				if !errors.Is(err, ErrAddressNotAllowed) {
					t.Errorf("expected ErrAddressNotAllowed for %q, got: %v", tt.address, err)
				}
				return
			}
			if err != nil {
				t.Errorf("expected %q to be allowed, got: %v", tt.address, err)
			}
		})
	}
}

func TestControlFuncErrFn(t *testing.T) {
	errLinkLocal := errors.New("link-local")
	control := Policy{}.ControlFunc(func(c Class) error {
		if c == ClassLinkLocal {
			return errLinkLocal
		}
		return nil
	})

	if err := control("tcp", "169.254.169.254:80", nil); !errors.Is(err, errLinkLocal) {
		t.Errorf("expected the mapped error, got: %v", err)
	}

	// errFn returning nil must fall back to the uniform error.
	if err := control("tcp", "127.0.0.1:80", nil); !errors.Is(err, ErrAddressNotAllowed) {
		t.Errorf("expected ErrAddressNotAllowed fallback, got: %v", err)
	}
}

type stubResolver map[string][]string

func (s stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	raw, ok := s[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	addrs := make([]netip.Addr, 0, len(raw))
	for _, r := range raw {
		addr, err := netip.ParseAddr(r)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}

	return addrs, nil
}

func TestCheckHost(t *testing.T) {
	resolver := stubResolver{
		"public.example.com":   {"1.1.1.1"},
		"internal.example.com": {"169.254.169.254"},
		"mixed.example.com":    {"1.1.1.1", "10.0.0.1"},
		"empty.example.com":    {},
	}

	tests := []struct {
		name    string
		policy  Policy
		host    string
		wantErr error
	}{
		{name: "public name", host: "public.example.com"},
		{name: "public literal", host: "1.1.1.1"},
		{name: "link-local literal", host: "169.254.169.254", wantErr: ErrAddressNotAllowed},
		{name: "link-local name", host: "internal.example.com", wantErr: ErrAddressNotAllowed},
		// a single blocked address in the answer must reject the host.
		{name: "mixed answer", host: "mixed.example.com", wantErr: ErrAddressNotAllowed},
		{name: "empty answer", host: "empty.example.com", wantErr: ErrAddressNotAllowed},
		{name: "empty host", host: "", wantErr: ErrAddressNotAllowed},
		{
			name:   "link-local name allowed by policy",
			policy: Policy{AllowLinkLocal: true},
			host:   "internal.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.CheckHost(context.Background(), resolver, tt.host)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected %v, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("expected %q to be allowed, got: %v", tt.host, err)
			}
		})
	}

	t.Run("resolution failure is surfaced", func(t *testing.T) {
		err := Policy{}.CheckHost(context.Background(), resolver, "unknown.example.com")
		if err == nil {
			t.Fatal("expected an error for an unresolvable host")
		}
		if errors.Is(err, ErrAddressNotAllowed) {
			t.Error("a resolution failure must not be reported as a blocked address")
		}
	})
}

func TestCheckURLHost(t *testing.T) {
	resolver := stubResolver{"public.example.com": {"1.1.1.1"}}

	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "https public", rawURL: "https://public.example.com/api", wantErr: false},
		{name: "http public with port", rawURL: "http://public.example.com:8080/api", wantErr: false},
		{name: "https link-local literal", rawURL: "https://169.254.169.254/latest", wantErr: true},
		{name: "http loopback literal", rawURL: "http://127.0.0.1:3000", wantErr: true},
		{name: "non http scheme", rawURL: "ssh://public.example.com/repo.git", wantErr: true},
		{name: "file scheme", rawURL: "file:///etc/passwd", wantErr: true},
		{name: "no host", rawURL: "https://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Policy{}.CheckURLHost(context.Background(), resolver, tt.rawURL)
			if tt.wantErr && err == nil {
				t.Errorf("expected %q to be rejected", tt.rawURL)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected %q to be allowed, got: %v", tt.rawURL, err)
			}
		})
	}
}
