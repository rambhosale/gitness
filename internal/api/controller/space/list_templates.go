// Copyright 2022 Harness Inc. All rights reserved.
// Use of this source code is governed by the Polyform Free Trial License
// that can be found in the LICENSE.md file for this repository.
package space

import (
	"context"
	"fmt"

	apiauth "github.com/harness/gitness/internal/api/auth"
	"github.com/harness/gitness/internal/auth"
	"github.com/harness/gitness/types"
	"github.com/harness/gitness/types/enum"
)

// ListTemplates lists the templates in a space.
func (c *Controller) ListTemplates(
	ctx context.Context,
	session *auth.Session,
	spaceRef string,
	filter types.ListQueryFilter,
) ([]*types.Template, int64, error) {
	space, err := c.spaceStore.FindByRef(ctx, spaceRef)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to find parent space: %w", err)
	}

	err = apiauth.CheckSpace(ctx, c.authorizer, session, space, enum.PermissionTemplateView, false)
	if err != nil {
		return nil, 0, fmt.Errorf("could not authorize: %w", err)
	}

	count, err := c.templateStore.Count(ctx, space.ID, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count templates in the space: %w", err)
	}

	templates, err := c.templateStore.List(ctx, space.ID, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list templates: %w", err)
	}

	return templates, count, nil
}