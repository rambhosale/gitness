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

package limiter

import (
	"context"
	"fmt"

	"github.com/harness/gitness/errors"

	"github.com/dustin/go-humanize"
	"github.com/rs/zerolog/log"
)

var ErrMaxNumReposReached = errors.New("maximum number of repositories reached")

type RepoQuotaStorageLevel string

const (
	RepoQuotaLevelSoft      RepoQuotaStorageLevel = "SOFT"
	RepoQuotaLevelHard      RepoQuotaStorageLevel = "HARD"
	RepoQuotaLevelOverLimit RepoQuotaStorageLevel = "OVER_LIMIT"
)

type TotalQuotaStorageLevel string

const (
	TotalQuotaLevelWarn      TotalQuotaStorageLevel = "WARN"
	TotalQuotaLevelCritical  TotalQuotaStorageLevel = "CRITICAL"
	TotalQuotaLevelOverLimit TotalQuotaStorageLevel = "OVER_LIMIT"
)

type RepoQuotaStorageError struct {
	Level     RepoQuotaStorageLevel
	Size      int64
	SoftLimit int64
	HardLimit int64
}

func (e *RepoQuotaStorageError) Error() string {
	switch e.Level {
	case RepoQuotaLevelSoft:
		return fmt.Sprintf("repo quota storage soft limit reached: %s, size: %d", e.Level, e.Size)
	case RepoQuotaLevelHard:
		return fmt.Sprintf("repo quota storage hard limit reached: %s, size: %d", e.Level, e.Size)
	case RepoQuotaLevelOverLimit:
		return fmt.Sprintf("repo quota storage over limit: %s, size: %d", e.Level, e.Size)
	}
	return fmt.Sprintf("unknown repo quota storage level: %s", e.Level)
}

// TotalQuotaStorageError reports a root space's total storage against its limit. Unlike
// the per-repository quota, the total storage thresholds are configured as percentages of
// Limit rather than as absolute sizes, so callers rendering a band or a threshold have
// to derive it from Limit.
type TotalQuotaStorageError struct {
	Level           TotalQuotaStorageLevel
	Size            int64
	Limit           int64
	WarnPercent     int
	CriticalPercent int
}

func (e *TotalQuotaStorageError) Error() string {
	switch e.Level {
	case TotalQuotaLevelWarn:
		return fmt.Sprintf("total quota storage warn limit reached: %s, size: %d", e.Level, e.Size)
	case TotalQuotaLevelCritical:
		return fmt.Sprintf("total quota storage critical limit reached: %s, size: %d", e.Level, e.Size)
	case TotalQuotaLevelOverLimit:
		return fmt.Sprintf("total quota storage over limit: %s, size: %d", e.Level, e.Size)
	}
	return fmt.Sprintf("unknown total quota storage level: %s", e.Level)
}

// Blocked reports whether the root space is over a storage limit that is enforced for it,
// the only level at which an operation is rejected. The lower levels are advisory: they
// are there to warn a pusher, and must not fail an operation.
func (e *TotalQuotaStorageError) Blocked() bool {
	return e.Level == TotalQuotaLevelOverLimit
}

// UserMessage renders the root space's storage state for an end user. Error() is written for
// logs and names the level that fired; this names what the user has to act on.
func (e *TotalQuotaStorageError) UserMessage() string {
	return fmt.Sprintf(
		"Storage limit exceeded: %s of %s used.",
		FormatQuotaBytes(e.Size),
		FormatQuotaBytes(e.Limit),
	)
}

// FormatQuotaBytes renders a byte count the way every quota surface does - the storage
// emails, the usage API and the push output - so the same figure reads identically
// wherever a user meets it.
func FormatQuotaBytes(bytes int64) string {
	if bytes < 0 {
		bytes = 0
	}
	return humanize.IBytes(uint64(bytes)) //nolint:gosec
}

// ResourceLimiter is an interface for managing resource limitation.
type ResourceLimiter interface {
	// RepoCount allows the creation of a specified number of repositories.
	RepoCount(ctx context.Context, spaceID int64, count int) error

	// RepoSize allows repository growth up to a limit for the given repoID.
	// It returns a *RepoQuotaStorageError naming the threshold the repository crossed,
	// of which only RepoQuotaLevelOverLimit rejects a write.
	RepoSize(ctx context.Context, repoID int64) error

	// RootSpaceStorage allows storage growth of a space's root space up to its limit,
	// returning a *TotalQuotaStorageError once a threshold is crossed. spaceID may
	// be any space in the hierarchy; implementations resolve its root space.
	// It reports the advisory levels too, so a caller with somewhere to show them - the
	// push output - can warn before the limit is reached; callers that can only allow or
	// reject act on TotalQuotaStorageError.Blocked.
	RootSpaceStorage(ctx context.Context, spaceID int64) error
}

// RejectIfStorageOverLimit is RootSpaceStorage for the callers that can only allow or
// reject: it returns an error only when the root space is over a storage limit that is
// enforced for it. The advisory levels are dropped, having nowhere to be shown here.
//
// A failure to measure storage at all does not reject either, matching the push path,
// which warns and lets the push through on the same failure: a metrics store or license
// service that is unreachable must not take repository creation, imports and restores down
// with it. This is a deliberate choice of availability over enforcement, and it is not
// free - for an import or a fork this check is the only gate, since the importer runs no
// check of its own and the data it pulls never passes the push path, so an operation
// allowed here is one whose storage is never accounted against the limit. Hence the log:
// nothing else records that the quota went unchecked.
func RejectIfStorageOverLimit(
	ctx context.Context,
	limiter ResourceLimiter,
	spaceID int64,
) error {
	err := limiter.RootSpaceStorage(ctx, spaceID)
	if err == nil {
		return nil
	}

	quotaErr, ok := errors.AsType[*TotalQuotaStorageError](err)
	if !ok {
		log.Ctx(ctx).Warn().Err(err).Int64("space_id", spaceID).
			Msg("failed to check total storage limit, allowing operation")
		return nil
	}

	if quotaErr.Blocked() {
		return quotaErr
	}

	return nil
}

var _ ResourceLimiter = Unlimited{}

type Unlimited struct {
}

// NewResourceLimiter creates a new instance of ResourceLimiter.
func NewResourceLimiter() ResourceLimiter {
	return Unlimited{}
}

func (Unlimited) RepoCount(context.Context, int64, int) error {
	return nil
}

func (Unlimited) RepoSize(context.Context, int64) error {
	return nil
}

func (Unlimited) RootSpaceStorage(context.Context, int64) error {
	return nil
}
