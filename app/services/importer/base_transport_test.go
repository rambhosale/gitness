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

package importer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harness/gitness/netpolicy"
)

// newTestImporter creates an Importer with nothing but the network policy set,
// which is all a provider lookup depends on.
func newTestImporter(policy netpolicy.Policy) *Importer {
	return &Importer{
		networkPolicy: policy,
		baseTransport: newBaseTransport(policy),
	}
}

// newLoopbackImporter creates an Importer that is allowed to reach a test server
// listening on loopback, which the default policy blocks.
func newLoopbackImporter() *Importer {
	return newTestImporter(netpolicy.Policy{AllowLoopback: true})
}

// closedPortOnLoopback returns a port on loopback that nothing listens on.
func closedPortOnLoopback(t *testing.T) int {
	t.Helper()

	var lc net.ListenConfig
	listener, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback: %v", err)
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is not *net.TCPAddr: %T", listener.Addr())
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	return tcpAddr.Port
}

func TestProviderRequest_BlockedByDefaultPolicy(t *testing.T) {
	imp := newTestImporter(netpolicy.Policy{})

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("the blocked destination was contacted")
	}))
	defer server.Close()

	tests := []struct {
		name string
		host string
	}{
		{name: "loopback", host: server.URL},
		{name: "link-local metadata", host: "http://169.254.169.254"},
		{name: "link-local from the report", host: "http://169.254.169.252:988"},
		{name: "private network", host: "http://10.1.2.3:8080"},
		{name: "carrier-grade NAT", host: "http://100.64.1.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := Provider{Type: ProviderTypeGitea, Host: tt.host, Password: "token"}

			_, _, err := imp.LoadRepositoryFromProvider(context.Background(), provider, "owner/repo")
			if err == nil {
				t.Fatalf("expected %q to be blocked, got no error", tt.host)
			}

			assertNoNetworkDetails(t, err)
		})
	}
}

// TestProviderRequest_OpenAndClosedPortsAreIndistinguishable is the regression
// test for the SSRF port scan: the error returned for a blocked address must not
// depend on whether anything listens on the requested port.
func TestProviderRequest_OpenAndClosedPortsAreIndistinguishable(t *testing.T) {
	imp := newTestImporter(netpolicy.Policy{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	openHost := server.URL
	closedHost := fmt.Sprintf("http://127.0.0.1:%d", closedPortOnLoopback(t))

	load := func(host string) error {
		provider := Provider{Type: ProviderTypeGitea, Host: host, Password: "token"}
		_, _, err := imp.LoadRepositoryFromProvider(context.Background(), provider, "owner/repo")
		if err == nil {
			t.Fatalf("expected an error for %q", host)
		}
		return err
	}

	openErr := load(openHost)
	closedErr := load(closedHost)

	if openErr.Error() != closedErr.Error() {
		t.Errorf("open and closed ports produce different errors:\n open:   %v\n closed: %v", openErr, closedErr)
	}

	assertNoNetworkDetails(t, openErr)
	assertNoNetworkDetails(t, closedErr)
}

func TestProviderRequest_AllowedByPolicy(t *testing.T) {
	imp := newLoopbackImporter()

	contacted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		contacted = true
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	provider := Provider{Type: ProviderTypeGitea, Host: server.URL, Password: "token"}

	_, _, err := imp.LoadRepositoryFromProvider(context.Background(), provider, "owner/repo")
	if err == nil {
		t.Fatal("expected the 404 of the test server to be reported as an error")
	}
	if !contacted {
		t.Error("expected the allowed destination to be contacted")
	}
}

// assertNoNetworkDetails verifies that a user facing error does not describe the
// state of the network - any such detail can be used as a probe.
func assertNoNetworkDetails(t *testing.T, err error) {
	t.Helper()

	forbidden := []string{
		"connection refused",
		"connect:",
		"dial tcp",
		"no such host",
		"i/o timeout",
		"network address is not allowed",
		"169.254.",
		"127.0.0.1",
		"10.1.2.3",
		"100.64.",
	}

	msg := err.Error()
	for _, f := range forbidden {
		if strings.Contains(msg, f) {
			t.Errorf("error message must not disclose %q, got: %s", f, msg)
		}
	}
}
