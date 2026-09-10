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

package controller

import (
	"encoding/json"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/harness/gitness/errors"
	"github.com/harness/gitness/git/hook"
	"github.com/harness/gitness/types"
	"github.com/harness/gitness/types/enum"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleViolations is the []types.RuleViolations a githook attaches to a blocking error,
// covering the fields the API/UI reads back: rule, bypassable, bypassed, and messages.
func sampleViolations() []types.RuleViolations {
	return []types.RuleViolations{
		{
			Rule: types.RuleInfo{
				RepoPath:   "space/repo",
				Identifier: "no-secrets",
				Type:       enum.RuleTypeBranch,
				State:      enum.RuleStateActive,
			},
			Bypassable: true,
			Bypassed:   false,
			Violations: []types.Violation{
				{Code: "secret.detected", Message: "secret detected in commit", Params: nil},
			},
		},
	}
}

// errorWithViolations reproduces the error a githook builds in git/hook/refupdate.go: the
// marshaled violations stored on an *errors.Error's details under the shared key.
func errorWithViolations(t *testing.T, violations []types.RuleViolations) error {
	t.Helper()
	raw, err := json.Marshal(violations)
	require.NoError(t, err)
	return errors.UnprocessableEntity("pre-receive hook blocked reference update").
		SetDetails(map[string]any{hook.RuleViolationsErrorDetailsKey: json.RawMessage(raw)})
}

// TestRuleViolationsFromError_RoundTrip checks the decode half of the propagation path:
// violations marshaled onto an error must come back out intact for the API to render,
// otherwise a 422-with-violations silently degrades to an opaque error.
func TestRuleViolationsFromError_RoundTrip(t *testing.T) {
	want := sampleViolations()

	got, ok := RuleViolationsFromError(errorWithViolations(t, want))

	require.True(t, ok)
	assert.Equal(t, want, got)
}

// TestRuleViolationsFromError_SurvivesWrapping guards that violations survive %w wrapping,
// since errors.Details relies on errors.As to reach the blocking error from the git layer.
func TestRuleViolationsFromError_SurvivesWrapping(t *testing.T) {
	want := sampleViolations()

	wrapped := fmt.Errorf("commit files: %w", errorWithViolations(t, want))
	got, ok := RuleViolationsFromError(wrapped)

	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestRuleViolationsFromError_NoViolations(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "nil error",
			err:  nil,
		},
		{
			name: "plain error",
			err:  stderrors.New("boom"),
		},
		{
			name: "typed error without details",
			err:  errors.UnprocessableEntity("pre-receive hook blocked reference update"),
		},
		{
			name: "typed error with unrelated details",
			err: errors.UnprocessableEntity("blocked").
				SetDetails(map[string]any{"something_else": "value"}),
		},
		{
			name: "empty violations list decodes to no violations",
			err:  errorWithViolations(t, []types.RuleViolations{}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := RuleViolationsFromError(tt.err)
			assert.False(t, ok)
			assert.Empty(t, got)
		})
	}
}
