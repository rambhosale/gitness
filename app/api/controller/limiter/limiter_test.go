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

package limiter_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/harness/gitness/app/api/controller/limiter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnlimited(t *testing.T) {
	ctx := context.Background()
	l := limiter.NewResourceLimiter()

	require.NoError(t, l.RepoCount(ctx, 1, 100))
	require.NoError(t, l.RepoSize(ctx, 1))
}

// TestTotalQuotaStorageErrorBlocked pins which level rejects an operation. Callers use
// Blocked to decide between failing a request and only warning a pusher, so a level
// wandering into the wrong group either blocks a push that must go through or lets one
// through that must not.
func TestTotalQuotaStorageErrorBlocked(t *testing.T) {
	tests := []struct {
		level   limiter.TotalQuotaStorageLevel
		blocked bool
	}{
		{level: limiter.TotalQuotaLevelWarn, blocked: false},
		{level: limiter.TotalQuotaLevelCritical, blocked: false},
		{level: limiter.TotalQuotaLevelOverLimit, blocked: true},
		{level: "", blocked: false},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			err := &limiter.TotalQuotaStorageError{Level: tt.level}
			assert.Equal(t, tt.blocked, err.Blocked())
		})
	}
}

// The user message is written into an API response, so a rewording is visible to users and
// has to be deliberate. The sizes are the same figures the push output and the storage
// emails quote, in the same units.
func TestTotalQuotaStorageErrorUserMessage(t *testing.T) {
	err := &limiter.TotalQuotaStorageError{
		Level:           limiter.TotalQuotaLevelOverLimit,
		Size:            62 * 1024 * 1024,
		Limit:           50 * 1024 * 1024,
		WarnPercent:     80,
		CriticalPercent: 95,
	}

	assert.Equal(t, "Storage limit exceeded: 62 MiB of 50 MiB used.", err.UserMessage())
}

// stubLimiter is Unlimited with a chosen RootSpaceStorage verdict.
type stubLimiter struct {
	limiter.Unlimited
	err error
}

func (s stubLimiter) RootSpaceStorage(context.Context, int64) error {
	return s.err
}

// TestRejectIfStorageOverLimit pins the fail-open contract the repository- and space-creating
// callers rely on: only an enforced over-limit verdict rejects them. In particular a failure
// to measure storage at all must not, or an unreachable metrics store would stop every repo
// from being created.
func TestRejectIfStorageOverLimit(t *testing.T) {
	overLimit := &limiter.TotalQuotaStorageError{Level: limiter.TotalQuotaLevelOverLimit}
	measureErr := errors.New("metrics store unreachable")

	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "under limit", err: nil, want: nil},
		{name: "warn is advisory", err: &limiter.TotalQuotaStorageError{Level: limiter.TotalQuotaLevelWarn}},
		{name: "critical is advisory", err: &limiter.TotalQuotaStorageError{Level: limiter.TotalQuotaLevelCritical}},
		{name: "over limit rejects", err: overLimit, want: overLimit},
		{name: "measurement failure is allowed", err: measureErr, want: nil},
		{name: "wrapped over limit rejects", err: fmt.Errorf("check: %w", overLimit), want: overLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := limiter.RejectIfStorageOverLimit(
				context.Background(), stubLimiter{err: tt.err}, 1,
			)
			if tt.want == nil {
				assert.NoError(t, err)
				return
			}
			assert.Equal(t, tt.want, err)
		})
	}
}

func TestFormatQuotaBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{bytes: 0, want: "0 B"},
		{bytes: 1024, want: "1.0 KiB"},
		{bytes: 50 * 1024 * 1024 * 1024, want: "50 GiB"},
		// A size is never negative, but a subtraction upstream could make one, and a
		// message reading "-1 B" would be worse than reading zero.
		{bytes: -1, want: "0 B"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, limiter.FormatQuotaBytes(tt.bytes))
		})
	}
}
