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

package repo

import (
	"context"
	"testing"

	"github.com/harness/gitness/app/api/controller/limiter"
	"github.com/harness/gitness/app/store"
	"github.com/harness/gitness/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passthroughTx is a dbtx.Transactor that runs the transaction function directly,
// standing in for a real database transaction in tests that don't need one.
type passthroughTx struct{}

func (passthroughTx) WithTx(ctx context.Context, fn func(ctx context.Context) error, _ ...any) error {
	return fn(ctx)
}

// restoreLimiterStub is Unlimited with a chosen RootSpaceStorage verdict, isolating
// RestoreNoAuth's storage check from its separate RepoCount check.
type restoreLimiterStub struct {
	limiter.Unlimited
	rootSpaceStorageErr error
}

func (s restoreLimiterStub) RootSpaceStorage(context.Context, int64) error {
	return s.rootSpaceStorageErr
}

// stubRepoStoreRestore is a store.RepoStore that only implements Restore, calling
// onRestore and echoing the repo back unchanged. Any other method call panics on the
// embedded nil interface, which is the point: it proves that method wasn't reached.
type stubRepoStoreRestore struct {
	store.RepoStore
	onRestore func()
}

func (s stubRepoStoreRestore) Restore(
	_ context.Context, repo *types.Repository, _ *string, _ *int64,
) (*types.Repository, error) {
	s.onRestore()
	return repo, nil
}

// TestRestoreNoAuth_StorageOverLimitBlocksRestore pins that RestoreNoAuth rejects a
// restore into a space over its enforced storage limit before ever reaching the
// store. repoStore is left nil on the controller: a call to repoStore.Restore would
// panic on the nil interface, which is what proves the check stopped the restore
// rather than merely returning some error.
func TestRestoreNoAuth_StorageOverLimitBlocksRestore(t *testing.T) {
	overLimit := &limiter.TotalQuotaStorageError{Level: limiter.TotalQuotaLevelOverLimit}

	c := &Controller{
		tx:              passthroughTx{},
		resourceLimiter: restoreLimiterStub{rootSpaceStorageErr: overLimit},
	}

	repo := &types.Repository{ID: 1, ParentID: 2}

	_, err := c.RestoreNoAuth(context.Background(), repo, nil, 2)

	require.Error(t, err)
	assert.ErrorIs(t, err, overLimit)
}

// TestRestoreNoAuth_StorageAdvisoryLevelDoesNotBlock pins that an advisory-level verdict
// (below the space's enforced limit) does not stop RestoreNoAuth from reaching the
// store, unlike the over-limit case above.
func TestRestoreNoAuth_StorageAdvisoryLevelDoesNotBlock(t *testing.T) {
	warn := &limiter.TotalQuotaStorageError{Level: limiter.TotalQuotaLevelWarn}

	restoreCalled := false
	c := &Controller{
		tx:              passthroughTx{},
		resourceLimiter: restoreLimiterStub{rootSpaceStorageErr: warn},
		repoStore:       stubRepoStoreRestore{onRestore: func() { restoreCalled = true }},
	}

	repo := &types.Repository{ID: 1, ParentID: 2}

	_, err := c.RestoreNoAuth(context.Background(), repo, nil, 2)

	require.NoError(t, err)
	assert.True(t, restoreCalled, "expected repoStore.Restore to be called")
}
