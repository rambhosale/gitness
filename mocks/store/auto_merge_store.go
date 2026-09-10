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

package store

import (
	"context"

	"github.com/harness/gitness/types"

	"github.com/stretchr/testify/mock"
)

type AutoMergeStore struct{ mock.Mock }

func (m *AutoMergeStore) Find(_ context.Context, pullreqID int64) (*types.AutoMerge, error) {
	args := m.Called(pullreqID)
	if v, _ := args.Get(0).(*types.AutoMerge); v != nil {
		return v, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *AutoMergeStore) Delete(_ context.Context, pullreqID int64) (bool, error) {
	args := m.Called(pullreqID)
	if v, ok := args.Get(0).(bool); ok {
		return v, args.Error(1)
	}
	return false, args.Error(1)
}

func (m *AutoMergeStore) Upsert(_ context.Context, autoMerge *types.AutoMerge) error {
	return m.Called(autoMerge).Error(0)
}
