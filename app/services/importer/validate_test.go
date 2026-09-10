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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harness/gitness/netpolicy"
)

func TestValidateProviderRepoSlug(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		slug         string
		wantErr      bool
	}{
		// --- path traversal ---
		{
			name:         "dot dot segments only",
			providerType: ProviderTypeGitea,
			slug:         "../../../..",
			wantErr:      true,
		},
		{
			name:         "traversal after a valid segment",
			providerType: ProviderTypeGitea,
			slug:         "owner/../../etc",
			wantErr:      true,
		},
		{name: "single dot segment", providerType: ProviderTypeGitea, slug: "owner/.", wantErr: true},
		{name: "dots only segment", providerType: ProviderTypeGitea, slug: "owner/...", wantErr: true},
		{
			name:         "percent encoded traversal",
			providerType: ProviderTypeGitea,
			slug:         "owner/..%2f..%2fetc",
			wantErr:      true,
		},
		{
			name:         "percent encoded separator",
			providerType: ProviderTypeGitea,
			slug:         "owner%2f..%2frepo",
			wantErr:      true,
		},

		// --- absolute and protocol relative URLs ---
		{name: "leading separator", providerType: ProviderTypeGitea, slug: "/etc/passwd", wantErr: true},
		{name: "trailing separator", providerType: ProviderTypeGitea, slug: "owner/repo/", wantErr: true},
		{name: "repeated separator", providerType: ProviderTypeGitea, slug: "owner//repo", wantErr: true},
		{
			name:         "protocol relative url",
			providerType: ProviderTypeAzure,
			slug:         "//attacker.example.com/repo",
			wantErr:      true,
		},
		{
			name:         "scheme in a segment",
			providerType: ProviderTypeAzure,
			slug:         "https:/attacker.example.com/repo",
			wantErr:      true,
		},
		{
			name:         "userinfo in a segment",
			providerType: ProviderTypeGitea,
			slug:         "owner@attacker.example.com/repo",
			wantErr:      true,
		},

		// --- query, fragment and control characters ---
		{name: "query injection", providerType: ProviderTypeGitea, slug: "owner/repo?admin=true", wantErr: true},
		{name: "fragment injection", providerType: ProviderTypeGitea, slug: "owner/repo#frag", wantErr: true},
		{name: "backslash", providerType: ProviderTypeGitea, slug: "owner\\repo/x", wantErr: true},
		{name: "newline", providerType: ProviderTypeGitea, slug: "owner/re\npo", wantErr: true},
		{name: "blank segment", providerType: ProviderTypeGitea, slug: "owner/   ", wantErr: true},

		// --- segment counts ---
		{name: "empty", providerType: ProviderTypeGitea, slug: "", wantErr: true},
		{name: "single segment", providerType: ProviderTypeGitea, slug: "repo", wantErr: true},
		{name: "too many segments", providerType: ProviderTypeGitea, slug: "owner/group/repo", wantErr: true},
		{name: "too long", providerType: ProviderTypeGitea, slug: "owner/" + strings.Repeat("a", 512), wantErr: true},

		// --- valid identifiers ---
		{name: "owner and repo", providerType: ProviderTypeGitea, slug: "owner/repo", wantErr: false},
		{name: "dotted repo name", providerType: ProviderTypeGitHub, slug: "owner/.github", wantErr: false},
		{name: "repo name with a dot", providerType: ProviderTypeGitHub, slug: "owner/repo.js", wantErr: false},
		{name: "dashes and underscores", providerType: ProviderTypeGitHub, slug: "my-org/my_repo.v2", wantErr: false},

		// --- gitlab subgroups ---
		{name: "gitlab flat project", providerType: ProviderTypeGitLab, slug: "group/project", wantErr: false},
		{name: "gitlab subgroup", providerType: ProviderTypeGitLab, slug: "group/sub/project", wantErr: false},
		{name: "gitlab nested subgroups", providerType: ProviderTypeGitLab, slug: "g/s1/s2/s3/p", wantErr: false},
		{name: "gitlab group only", providerType: ProviderTypeGitLab, slug: "group", wantErr: true},
		{
			name:         "gitlab too deeply nested",
			providerType: ProviderTypeGitLab,
			slug:         strings.Repeat("g/", maxProviderSlugSegments) + "p",
			wantErr:      true,
		},

		// --- azure ---
		{name: "azure full slug", providerType: ProviderTypeAzure, slug: "org/project/repo", wantErr: false},
		{name: "azure project name with space", providerType: ProviderTypeAzure, slug: "org/my proj/repo", wantErr: false},
		{name: "azure without project", providerType: ProviderTypeAzure, slug: "org/repo", wantErr: true},

		// --- harness ---
		{name: "harness account scope", providerType: ProviderTypeHarness, slug: "acc/repo", wantErr: false},
		{name: "harness org scope", providerType: ProviderTypeHarness, slug: "acc/org/repo", wantErr: false},
		{name: "harness project scope", providerType: ProviderTypeHarness, slug: "acc/org/proj/repo", wantErr: false},
		{name: "harness repo only", providerType: ProviderTypeHarness, slug: "repo", wantErr: true},
		{name: "harness too many segments", providerType: ProviderTypeHarness, slug: "a/b/c/d/e", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProviderRepoSlug(tt.providerType, tt.slug)
			if tt.wantErr && err == nil {
				t.Errorf("expected %q to be rejected for %s", tt.slug, tt.providerType)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected %q to be accepted for %s, got: %v", tt.slug, tt.providerType, err)
			}
		})
	}
}

func TestValidateProviderSpaceSlug(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		slug         string
		wantErr      bool
	}{
		{name: "github org", providerType: ProviderTypeGitHub, slug: "myorg", wantErr: false},
		{name: "github org with a path", providerType: ProviderTypeGitHub, slug: "myorg/team", wantErr: true},
		{name: "github traversal", providerType: ProviderTypeGitHub, slug: "..", wantErr: true},
		{name: "bitbucket workspace", providerType: ProviderTypeBitbucket, slug: "myworkspace", wantErr: false},
		{name: "gitea user", providerType: ProviderTypeGitea, slug: "myuser", wantErr: false},
		{name: "gitlab group", providerType: ProviderTypeGitLab, slug: "mygroup", wantErr: false},
		{name: "gitlab subgroup", providerType: ProviderTypeGitLab, slug: "mygroup/sub", wantErr: false},
		{name: "azure org and project", providerType: ProviderTypeAzure, slug: "org/project", wantErr: false},
		{name: "azure org only", providerType: ProviderTypeAzure, slug: "org", wantErr: true},
		{name: "harness account scope", providerType: ProviderTypeHarness, slug: "acc/org", wantErr: false},
		{name: "empty", providerType: ProviderTypeGitHub, slug: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProviderSpaceSlug(tt.providerType, tt.slug)
			if tt.wantErr && err == nil {
				t.Errorf("expected %q to be rejected for %s", tt.slug, tt.providerType)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected %q to be accepted for %s, got: %v", tt.slug, tt.providerType, err)
			}
		})
	}
}

func TestValidateProviderHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		policy  netpolicy.Policy
		wantErr bool
	}{
		{name: "https host", host: "https://gitea.example.com", wantErr: false},
		{name: "http host with a port", host: "http://gitea.example.com:3000", wantErr: false},
		// a provider hosted under a sub path is a supported setup.
		{name: "host with a base path", host: "https://code.example.com/gitlab", wantErr: false},
		{name: "host with a trailing slash", host: "https://code.example.com/gitlab/", wantErr: false},

		{name: "link-local from the report", host: "http://169.254.169.252:987", wantErr: true},
		{name: "metadata endpoint", host: "http://169.254.169.254", wantErr: true},
		{name: "loopback literal", host: "http://127.0.0.1:3000", wantErr: true},
		{name: "localhost", host: "http://localhost:3000", wantErr: true},
		{name: "localhost uppercase", host: "http://LOCALHOST:3000", wantErr: true},
		{name: "private literal", host: "https://10.1.2.3", wantErr: true},
		{name: "ipv4 mapped loopback", host: "http://[::ffff:127.0.0.1]", wantErr: true},

		{name: "loopback allowed by policy", host: "http://127.0.0.1:3000",
			policy: netpolicy.Policy{AllowLoopback: true}, wantErr: false},
		{name: "localhost allowed by policy", host: "http://localhost:3000",
			policy: netpolicy.Policy{AllowLoopback: true}, wantErr: false},

		{name: "no scheme", host: "gitea.example.com", wantErr: true},
		{name: "unsupported scheme", host: "ftp://gitea.example.com", wantErr: true},
		{name: "file scheme", host: "file:///etc/passwd", wantErr: true},
		{name: "no host", host: "https://", wantErr: true},
		{name: "credentials in host", host: "https://user:pass@gitea.example.com", wantErr: true},
		{name: "query in host", host: "https://gitea.example.com?a=b", wantErr: true},
		{name: "fragment in host", host: "https://gitea.example.com#frag", wantErr: true},
		{name: "too long", host: "https://" + strings.Repeat("a", maxProviderHostLength), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newTestImporter(tt.policy).validateProviderHost(tt.host)
			if tt.wantErr && err == nil {
				t.Errorf("expected %q to be rejected", tt.host)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected %q to be accepted, got: %v", tt.host, err)
			}
		})
	}
}

// TestLoadRepositoryFromProvider_TraversalNeverReachesTheProvider verifies that
// the payload of the SSRF report is rejected before any request is made, so the
// provider credentials are never sent to an arbitrary path of the host.
func TestLoadRepositoryFromProvider_TraversalNeverReachesTheProvider(t *testing.T) {
	imp := newLoopbackImporter()

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("the provider was contacted at %q", r.URL.Path)
	}))
	defer server.Close()

	provider := Provider{Type: ProviderTypeGitea, Host: server.URL, Username: "user", Password: "token"}

	_, _, err := imp.LoadRepositoryFromProvider(context.Background(), provider, "../../../..")
	if err == nil {
		t.Fatal("expected the traversal identifier to be rejected")
	}
	if strings.Contains(err.Error(), "../../../..") {
		t.Errorf("the error must not echo the identifier back, got: %s", err)
	}
}
