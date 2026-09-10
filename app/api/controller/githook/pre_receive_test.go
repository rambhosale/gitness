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

package githook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/harness/gitness/app/api/controller/limiter"
	"github.com/harness/gitness/app/services/refcache"
	storecache "github.com/harness/gitness/app/store/cache"
	gitness_store "github.com/harness/gitness/store"
	"github.com/harness/gitness/types"
	"github.com/harness/gitness/types/enum"

	"github.com/fatih/color"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRepoID int64 = 42
const testSpaceID int64 = 7

const mib = int64(1024 * 1024)

// rootSpaceStorageCall records the arguments of a single RootSpaceStorage call.
type rootSpaceStorageCall struct {
	spaceID       int64
	additionalKiB int64
}

// limiterMock is a limiter.ResourceLimiter that returns preconfigured errors and
// records the calls it received.
type limiterMock struct {
	repoSizeErr         error
	rootSpaceStorageErr error

	repoSizeCalls         []int64
	rootSpaceStorageCalls []rootSpaceStorageCall
}

func (l *limiterMock) RepoCount(context.Context, int64, int) error {
	return nil
}

func (l *limiterMock) RepoSize(_ context.Context, repoID int64) error {
	l.repoSizeCalls = append(l.repoSizeCalls, repoID)
	return l.repoSizeErr
}

func (l *limiterMock) RootSpaceStorage(_ context.Context, spaceID int64) error {
	l.rootSpaceStorageCalls = append(
		l.rootSpaceStorageCalls,
		rootSpaceStorageCall{spaceID: spaceID},
	)
	return l.rootSpaceStorageErr
}

var _ limiter.ResourceLimiter = (*limiterMock)(nil)

// repoIDCacheMock serves a single repository by its ID.
type repoIDCacheMock struct {
	repo *types.RepositoryCore
}

func (repoIDCacheMock) Stats() (int64, int64) { return 0, 0 }

func (repoIDCacheMock) Evict(context.Context, int64) {}

func (c repoIDCacheMock) Get(_ context.Context, id int64) (*types.RepositoryCore, error) {
	if c.repo == nil || c.repo.ID != id {
		return nil, gitness_store.ErrResourceNotFound
	}
	return c.repo, nil
}

func newTestController(repo *types.RepositoryCore, l limiter.ResourceLimiter) *Controller {
	return &Controller{
		repoFinder: refcache.NewRepoFinder(
			nil,
			nil,
			repoIDCacheMock{repo: repo},
			nil,
			storecache.Evictor[*types.RepositoryCore]{},
		),
		limiter: l,
	}
}

func newTestRepo() *types.RepositoryCore {
	return &types.RepositoryCore{
		ID:            testRepoID,
		ParentID:      testSpaceID,
		Identifier:    "repo",
		Path:          "space/repo",
		GitUID:        "git-uid",
		DefaultBranch: "main",
		State:         enum.RepoStateActive,
		Type:          enum.RepoTypeNormal,
	}
}

// repoQuotaErr is the verdict the limiter returns for a repository of sizeMiB, against a
// 30 MiB advisory limit and a 60 MiB hard one.
func repoQuotaErr(level limiter.RepoQuotaStorageLevel, sizeMiB int64) error {
	return &limiter.RepoQuotaStorageError{
		Level:     level,
		Size:      sizeMiB * mib,
		SoftLimit: 30 * mib,
		HardLimit: 60 * mib,
	}
}

// totalQuotaErr is the verdict the limiter returns for a root space using sizeMiB of a
// 50 MiB limit, warning at 80% of it and turning critical at 95%.
func totalQuotaErr(level limiter.TotalQuotaStorageLevel, sizeMiB int64) error {
	return &limiter.TotalQuotaStorageError{
		Level:           level,
		Size:            sizeMiB * mib,
		Limit:           50 * mib,
		WarnPercent:     80,
		CriticalPercent: 95,
	}
}

// archivedRejection is the rejection an archived repository earns after the quota checks.
// The quota tests push to an archived repository on purpose: it forces an exit that
// preserves output.Messages, which is the only way to see a warning that does not block.
func archivedRejection() *string {
	return strPtr(
		fmt.Sprintf("Push not allowed when repository is in '%s' state", enum.RepoStateArchived),
	)
}

// TestPreReceive_StorageLimits covers how PreReceive turns the limiter's verdicts into hook
// output. The bars are compared verbatim because they are written straight into git's push
// output, so a change to one is visible to every pusher.
func TestPreReceive_StorageLimits(t *testing.T) {
	// The bars are compared verbatim, so they must not depend on the terminal the test
	// happens to run in.
	color.NoColor = true

	tests := []struct {
		name                string
		repoSizeErr         error
		rootSpaceStorageErr error
		// repoState and opType decide where PreReceive exits, which is what determines
		// whether accumulated messages survive.
		repoState        enum.RepoState
		opType           enum.GitOpType
		expectedOutErr   *string
		expectedMessages []string
	}{
		{
			name:      "within limits",
			repoState: enum.RepoStateActive,
			opType:    enum.GitOpTypeAPIRefsOnly,
		},
		{
			name:        "repo size soft limit only warns",
			repoSizeErr: repoQuotaErr(limiter.RepoQuotaLevelSoft, 35),
			repoState:   enum.RepoStateArchived,
			opType:      enum.GitOpTypeGitPush,
			// The push is stopped by the archived state, not by the quota.
			expectedOutErr: archivedRejection(),
			expectedMessages: []string{
				"Repository storage",
				"  [███████████░░░░░░░░░]  58%  35 MiB / 60 MiB  WARNING",
				"",
			},
		},
		{
			// A repository over the hard limit on a plan the limit is not enforced for is
			// over its last threshold, so it reads OVER LIMIT, but it is never blocked.
			name:           "repo size hard limit only warns when not enforced",
			repoSizeErr:    repoQuotaErr(limiter.RepoQuotaLevelHard, 62),
			repoState:      enum.RepoStateArchived,
			opType:         enum.GitOpTypeGitPush,
			expectedOutErr: archivedRejection(),
			expectedMessages: []string{
				"Repository storage",
				"  [████████████████████] 100%  62 MiB / 60 MiB  OVER LIMIT",
				"",
			},
		},
		{
			// The quota rejection wins over the archived-state one below it, which proves
			// PreReceive stops as soon as a quota blocks the push.
			name:           "repo size over limit blocks push",
			repoSizeErr:    repoQuotaErr(limiter.RepoQuotaLevelOverLimit, 62),
			repoState:      enum.RepoStateArchived,
			opType:         enum.GitOpTypeGitPush,
			expectedOutErr: strPtr("Repository storage limit exceeded; pushes are blocked."),
			expectedMessages: []string{
				"Repository storage",
				"  [████████████████████] 100%  62 MiB / 60 MiB  OVER LIMIT",
				"",
			},
		},
		{
			// A blocked push must be reported even for an operation that otherwise returns
			// an empty output.
			name:           "repo size over limit blocks refs only operation",
			repoSizeErr:    repoQuotaErr(limiter.RepoQuotaLevelOverLimit, 62),
			repoState:      enum.RepoStateActive,
			opType:         enum.GitOpTypeAPIRefsOnly,
			expectedOutErr: strPtr("Repository storage limit exceeded; pushes are blocked."),
			expectedMessages: []string{
				"Repository storage",
				"  [████████████████████] 100%  62 MiB / 60 MiB  OVER LIMIT",
				"",
			},
		},
		{
			name:                "total storage warn threshold only warns",
			rootSpaceStorageErr: totalQuotaErr(limiter.TotalQuotaLevelWarn, 41),
			repoState:           enum.RepoStateArchived,
			opType:              enum.GitOpTypeGitPush,
			expectedOutErr:      archivedRejection(),
			expectedMessages: []string{
				"Total storage",
				"  [████████████████░░░░]  82%  41 MiB / 50 MiB  WARNING",
				"",
			},
		},
		{
			name:                "total storage critical threshold only warns",
			rootSpaceStorageErr: totalQuotaErr(limiter.TotalQuotaLevelCritical, 48),
			repoState:           enum.RepoStateArchived,
			opType:              enum.GitOpTypeGitPush,
			expectedOutErr:      archivedRejection(),
			expectedMessages: []string{
				"Total storage",
				"  [███████████████████░]  96%  48 MiB / 50 MiB  CRITICAL",
				"",
			},
		},
		{
			name:                "total storage over limit blocks push",
			rootSpaceStorageErr: totalQuotaErr(limiter.TotalQuotaLevelOverLimit, 62),
			repoState:           enum.RepoStateActive,
			opType:              enum.GitOpTypeGitPush,
			expectedOutErr:      strPtr("Total storage limit exceeded; pushes are blocked."),
			expectedMessages: []string{
				"Total storage",
				"  [████████████████████] 100%  62 MiB / 50 MiB  OVER LIMIT",
				"",
			},
		},
		{
			// The limiter wraps nothing today, but a caller in between might, and the
			// verdict must survive it.
			name: "wrapped total storage verdict is still recognised",
			rootSpaceStorageErr: fmt.Errorf(
				"space %d: %w", testSpaceID, totalQuotaErr(limiter.TotalQuotaLevelOverLimit, 62),
			),
			repoState:      enum.RepoStateActive,
			opType:         enum.GitOpTypeGitPush,
			expectedOutErr: strPtr("Total storage limit exceeded; pushes are blocked."),
			expectedMessages: []string{
				"Total storage",
				"  [████████████████████] 100%  62 MiB / 50 MiB  OVER LIMIT",
				"",
			},
		},
		{
			// Both quotas are reported, so the pusher sees which one to act on. The
			// total storage rejection is the one shown, because it is checked last.
			name:                "both quotas are reported",
			repoSizeErr:         repoQuotaErr(limiter.RepoQuotaLevelOverLimit, 62),
			rootSpaceStorageErr: totalQuotaErr(limiter.TotalQuotaLevelOverLimit, 62),
			repoState:           enum.RepoStateActive,
			opType:              enum.GitOpTypeGitPush,
			expectedOutErr:      strPtr("Total storage limit exceeded; pushes are blocked."),
			expectedMessages: []string{
				"Repository storage",
				"  [████████████████████] 100%  62 MiB / 60 MiB  OVER LIMIT",
				"",
				"Total storage",
				"  [████████████████████] 100%  62 MiB / 50 MiB  OVER LIMIT",
				"",
			},
		},
		{
			// Failing to measure storage must not stop a push: an outage in the metric
			// store or the license service cannot be allowed to stop every write.
			name:                "unmeasurable storage fails open",
			repoSizeErr:         errors.New("repo store down"),
			rootSpaceStorageErr: errors.New("metrics store down"),
			repoState:           enum.RepoStateActive,
			opType:              enum.GitOpTypeAPIRefsOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &limiterMock{
				repoSizeErr:         tt.repoSizeErr,
				rootSpaceStorageErr: tt.rootSpaceStorageErr,
			}

			repo := newTestRepo()
			repo.State = tt.repoState

			out, err := newTestController(repo, l).PreReceive(
				context.Background(),
				nil,
				nil,
				types.GithookPreReceiveInput{
					GithookInputBase: types.GithookInputBase{
						RepoID:        testRepoID,
						OperationType: tt.opType,
					},
				},
			)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedOutErr, out.Error)
			assert.Equal(t, tt.expectedMessages, out.Messages)

			// Both quotas are always measured: a repository under its own limit can still
			// sit in a root space that is over the total storage limit.
			assert.Equal(t, []int64{testRepoID}, l.repoSizeCalls)
			// the total storage quota is enforced against the repo's parent space
			assert.Equal(t,
				[]rootSpaceStorageCall{{spaceID: testSpaceID, additionalKiB: 0}},
				l.rootSpaceStorageCalls,
			)
		})
	}
}

// TestPreReceive_StorageMeasurementFailureIsLogged pins the other half of the fail-open
// contract that TestPreReceive_StorageLimits's "unmeasurable storage fails open" case
// doesn't reach: not just that a measurement failure lets the push through, but that it
// is logged on its way through, since nothing else would record why the quota went
// unchecked.
func TestPreReceive_StorageMeasurementFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	ctx := zerolog.New(&buf).WithContext(context.Background())

	l := &limiterMock{
		repoSizeErr:         errors.New("repo store down"),
		rootSpaceStorageErr: errors.New("metrics store down"),
	}

	repo := newTestRepo()
	repo.State = enum.RepoStateActive

	out, err := newTestController(repo, l).PreReceive(
		ctx,
		nil,
		nil,
		types.GithookPreReceiveInput{
			GithookInputBase: types.GithookInputBase{
				RepoID:        testRepoID,
				OperationType: enum.GitOpTypeAPIRefsOnly,
			},
		},
	)

	require.NoError(t, err)
	assert.Nil(t, out.Error)
	assert.Nil(t, out.Messages)

	logs := buf.String()
	assert.Contains(t, logs, "failed to check repository size limit, allowing push")
	assert.Contains(t, logs, "repo store down")
	assert.Contains(t, logs, "failed to check total storage limit, allowing push")
	assert.Contains(t, logs, "metrics store down")
}

// TestPreReceive_StorageLimitsSkipped documents the operations that must not be
// subject to storage quotas because they never add content.
func TestPreReceive_StorageLimitsSkipped(t *testing.T) {
	tests := []struct {
		name     string
		repoType enum.RepoType
		opType   enum.GitOpType
	}{
		{
			name:     "merge queue fast forward",
			repoType: enum.RepoTypeNormal,
			opType:   enum.GitOpTypeMergeQueue,
		},
		{
			name:     "linked repository sync",
			repoType: enum.RepoTypeLinked,
			opType:   enum.GitOpTypeAPILinkedSync,
		},
		{
			name:     "repository management",
			repoType: enum.RepoTypeNormal,
			opType:   enum.GitOpTypeManageRepo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// any limiter call would block the push, so an empty output proves the
			// limiter wasn't consulted
			l := &limiterMock{
				repoSizeErr:         repoQuotaErr(limiter.RepoQuotaLevelOverLimit, 62),
				rootSpaceStorageErr: totalQuotaErr(limiter.TotalQuotaLevelOverLimit, 62),
			}

			repo := newTestRepo()
			repo.Type = tt.repoType

			out, err := newTestController(repo, l).PreReceive(
				context.Background(),
				nil,
				nil,
				types.GithookPreReceiveInput{
					GithookInputBase: types.GithookInputBase{
						RepoID:        testRepoID,
						OperationType: tt.opType,
					},
				},
			)
			require.NoError(t, err)

			assert.Empty(t, l.repoSizeCalls)
			assert.Empty(t, l.rootSpaceStorageCalls)

			if tt.opType == enum.GitOpTypeManageRepo {
				// management operations are rejected before the repo is even loaded
				require.NotNil(t, out.Error)
				return
			}
			assert.Nil(t, out.Error)
		})
	}
}

// TestOperationAllowsPushBypass pins the bypass gate per operation type: a security
// boundary where flipping api_content back to bypassable would silently skip push rules
// for any actor on the bypass list. Every op type is asserted, not just bypassable ones.
func TestOperationAllowsPushBypass(t *testing.T) {
	tests := []struct {
		opType enum.GitOpType
		want   bool
	}{
		{enum.GitOpTypeGitPush, true},
		{enum.GitOpTypeAPIContentBypassRules, true},
		{enum.GitOpTypeAPIContent, false},
		{enum.GitOpTypeAPIRefsOnly, false},
		{enum.GitOpTypeAPISystemRefs, false},
		{enum.GitOpTypeAPILinkedSync, false},
		{enum.GitOpTypeManageRepo, false},
		{enum.GitOpTypeMergeQueue, false},
		{enum.GitOpType(""), false},
		{enum.GitOpType("unknown_op"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.opType), func(t *testing.T) {
			assert.Equal(t, tt.want, operationAllowsPushBypass(tt.opType))
		})
	}
}

func strPtr(s string) *string {
	return &s
}
