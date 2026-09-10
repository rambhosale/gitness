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
	"net/url"
	"strings"

	"github.com/harness/gitness/app/api/usererror"
	"github.com/harness/gitness/netpolicy"
)

const (
	// maxProviderHostLength defines the max allowed length of a provider host.
	maxProviderHostLength = 2048
	// maxProviderSlugLength defines the max allowed length of a provider side
	// repository or space identifier.
	maxProviderSlugLength = 512
	// maxProviderSlugSegments defines the max number of path segments of a
	// provider side identifier, for the providers that support nesting.
	maxProviderSlugSegments = 10
)

// providerSlugForbiddenChars lists the characters that must not appear in a
// segment of a provider side identifier.
//
// IMPORTANT: the identifier is interpolated into the path of the provider API
// request, which is then resolved against the provider host. These are the
// characters that change the meaning of the resulting URL: percent encoding
// (which can re-introduce a path separator), the query and fragment delimiters,
// and the scheme and userinfo delimiters, which can turn the relative path into
// an absolute URL pointing at an entirely different host.
const providerSlugForbiddenChars = "%\\?#:@[]<>\"{}|^`"

// validateProviderHost validates a user provided provider host.
//
// NOTE: the address check is an early, best-effort one for the convenience of a
// clear error - the authoritative check happens on the resolved address when the
// connection is dialed, see base_transport.go.
func (r *Importer) validateProviderHost(rawHost string) error {
	if len(rawHost) > maxProviderHostLength {
		return usererror.BadRequestf("The provider host can be at most %d characters long.", maxProviderHostLength)
	}

	parsed, err := url.Parse(rawHost)
	if err != nil {
		return usererror.BadRequest("The provider host is not a valid URL.")
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return usererror.BadRequest("The scheme of the provider host must be either http or https.")
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return usererror.BadRequest("The provider host has to have a non-empty host.")
	}

	if parsed.User != nil {
		return usererror.BadRequest("The provider host must not contain credentials.")
	}

	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return usererror.BadRequest("The provider host must not contain a query or a fragment.")
	}

	// NOTE: a single message for every rejected address on purpose - naming the
	// reason would disclose how the destination is classified.
	if strings.EqualFold(hostname, "localhost") && !r.networkPolicy.AllowLoopback {
		return usererror.BadRequest("The provider host is not allowed.")
	}

	if ip := net.ParseIP(hostname); ip != nil && !r.networkPolicy.Allows(netpolicy.Classify(ip)) {
		return usererror.BadRequest("The provider host is not allowed.")
	}

	return nil
}

// validateProviderRepoSlug validates a user provided repository identifier of a
// provider, e.g. "owner/repository".
func validateProviderRepoSlug(providerType ProviderType, slug string) error {
	minSegments, maxSegments := 2, 2

	//nolint:exhaustive // the remaining providers use the owner/repository default above.
	switch providerType {
	case ProviderTypeGitLab:
		// gitlab projects can live in nested subgroups.
		maxSegments = maxProviderSlugSegments
	case ProviderTypeAzure:
		// organization/project/repository.
		minSegments, maxSegments = 3, 3
	case ProviderTypeHarness:
		// account[/organization[/project]]/repository.
		minSegments, maxSegments = 2, 4
	}

	return validateProviderSlug(slug, "repository", minSegments, maxSegments)
}

// validateProviderSpaceSlug validates a user provided space identifier of a
// provider, e.g. a github organization or a gitlab group.
func validateProviderSpaceSlug(providerType ProviderType, slug string) error {
	minSegments, maxSegments := 1, 1

	//nolint:exhaustive // the remaining providers use the single segment default above.
	switch providerType {
	case ProviderTypeGitLab:
		// gitlab groups can be nested.
		maxSegments = maxProviderSlugSegments
	case ProviderTypeAzure:
		// organization/project.
		minSegments, maxSegments = 2, 3
	case ProviderTypeHarness:
		// account[/organization[/project]].
		minSegments, maxSegments = 2, 4
	}

	return validateProviderSlug(slug, "space", minSegments, maxSegments)
}

func validateProviderSlug(slug string, kind string, minSegments int, maxSegments int) error {
	if slug == "" {
		return usererror.BadRequestf("Provider %s identifier is missing", kind)
	}

	if len(slug) > maxProviderSlugLength {
		return usererror.BadRequestf("The provider %s identifier can be at most %d characters long.",
			kind, maxProviderSlugLength)
	}

	// NOTE: an empty segment rejects a leading, trailing or repeated "/", which
	// keeps the identifier from resolving to the root of the provider host or,
	// worse, to a protocol relative URL ("//host/path") pointing somewhere else.
	segments := strings.Split(slug, "/")
	for _, segment := range segments {
		if !isValidProviderSlugSegment(segment) {
			return usererror.BadRequestf("The provider %s identifier is invalid.", kind)
		}
	}

	if len(segments) < minSegments || len(segments) > maxSegments {
		if minSegments == maxSegments {
			return usererror.BadRequestf(
				"The provider %s identifier must consist of exactly %d path segments separated by '/'.",
				kind, minSegments)
		}

		return usererror.BadRequestf(
			"The provider %s identifier must consist of %d to %d path segments separated by '/'.",
			kind, minSegments, maxSegments)
	}

	return nil
}

func isValidProviderSlugSegment(segment string) bool {
	if strings.TrimSpace(segment) == "" {
		return false
	}

	// "." and ".." (and any other dots-only segment) traverse the API path of the
	// provider, which is what allows an arbitrary path to be requested.
	if strings.Trim(segment, ".") == "" {
		return false
	}

	if strings.ContainsAny(segment, providerSlugForbiddenChars) {
		return false
	}

	for _, r := range segment {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}

	return true
}
