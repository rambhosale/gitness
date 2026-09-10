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
	"net"
	"net/http"
	"time"

	"github.com/harness/gitness/netpolicy"
)

// newBaseTransport creates the RoundTripper underneath every request to an
// import provider. The provided policy decides which destinations may be
// reached.
//
// The policy is enforced from net.Dialer.Control, which runs on the resolved
// address before the connect syscall, so a blocked destination is never
// contacted at all. Connecting first and inspecting the remote address
// afterwards would leak whether an internal port is open, as the caller could
// tell a successful connection apart from a refused one.
func newBaseTransport(policy netpolicy.Policy) http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck

	// the client verifies the server's certificate chain and host name
	tr.TLSClientConfig.InsecureSkipVerify = false

	// create basic net.Dialer (Similar to what is used by http.DefaultTransport),
	// blocking connections to anything but the addresses the policy allows.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		// nil error mapper: the destination is provided by any authenticated
		// user, so all rejections must be indistinguishable.
		Control: policy.ControlFunc(nil),
	}

	tr.DialContext = dialer.DialContext

	return tr
}
