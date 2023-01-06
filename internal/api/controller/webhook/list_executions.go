// Copyright 2022 Harness Inc. All rights reserved.
// Use of this source code is governed by the Polyform Free Trial License
// that can be found in the LICENSE.md file for this repository.

package webhook

import (
	"context"
	"fmt"

	"github.com/harness/gitness/internal/auth"
	"github.com/harness/gitness/types"
	"github.com/harness/gitness/types/enum"
)

// ListExecutions returns the executions of the webhook.
func (c *Controller) ListExecutions(
	ctx context.Context,
	session *auth.Session,
	repoRef string,
	webhookID int64,
	filter *types.WebhookExecutionFilter,
) ([]*types.WebhookExecution, error) {
	repo, err := c.getRepoCheckAccess(ctx, session, repoRef, enum.PermissionRepoView)
	if err != nil {
		return nil, err
	}

	// get the webhook and ensure it belongs to us
	webhook, err := c.getWebhookVerifyOwnership(ctx, repo.ID, webhookID)
	if err != nil {
		return nil, err
	}

	// get webhook executions
	webhookExecutions, err := c.webhookExecutionStore.ListForWebhook(ctx, webhook.ID, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list webhook executions for webhook %d: %w", webhook.ID, err)
	}

	return webhookExecutions, nil
}