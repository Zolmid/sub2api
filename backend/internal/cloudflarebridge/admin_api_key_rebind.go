package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// AdminAPIKeyGroupRebindControlPlane is deliberately separate from generic key
// updates. The Worker operation may atomically add an exclusive-group grant,
// while the ordinary patch protocol must never gain that authority.
type AdminAPIKeyGroupRebindControlPlane interface {
	RebindManagedAPIKeyGroup(context.Context, int64, int64) (*ManagedAPIKeyGroupRebindResult, error)
}

type ManagedAPIKeyGroupRebindResult struct {
	APIKey                 *service.APIKey
	Group                  *service.Group
	AutoGrantedGroupAccess bool
	GrantedGroupID         *int64
	GrantedGroupName       string
}

// cloudflareAdminAPIKeyRebindRequest accepts exactly one positive, canonical
// Cloudflare request ID. A custom decoder keeps a missing/null group_id and a
// non-object JSON value distinct from a successful zero-value Go struct.
type cloudflareAdminAPIKeyRebindRequest struct {
	GroupID cloudflareRequestID
}

func (r *cloudflareAdminAPIKeyRebindRequest) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("request must be an object containing only group_id")
	}
	var raw json.RawMessage
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok || name != "group_id" || raw != nil {
			return errors.New("request must be an object containing only group_id")
		}
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return errors.New("request must be an object containing only group_id")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values are not allowed")
	}
	if raw == nil || string(raw) == "null" {
		return errors.New("group_id is required")
	}
	var groupID cloudflareRequestID
	if err := groupID.UnmarshalJSON(raw); err != nil {
		return fmt.Errorf("invalid group_id: %w", err)
	}
	r.GroupID = groupID
	return nil
}

func (h *cloudflareAdminAPIHandler) apiKeyGroupRebinds() (AdminAPIKeyGroupRebindControlPlane, error) {
	mutations, ok := h.control.(AdminAPIKeyGroupRebindControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return mutations, nil
}

// RebindAPIKeyGroup is the Cloudflare-mode implementation of the public
// PUT /api/v1/admin/api-keys/:id contract. It intentionally omits all quota,
// rate-limit, and unbind controls supported by the traditional handler.
func (h *cloudflareAdminAPIHandler) RebindAPIKeyGroup(c *gin.Context) {
	keyID, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	var request cloudflareAdminAPIKeyRebindRequest
	if err := decodeCloudflareJSON(c, &request); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	mutations, err := h.apiKeyGroupRebinds()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := mutations.RebindManagedAPIKeyGroup(c.Request.Context(), keyID, int64(request.GroupID))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if result == nil || result.APIKey == nil || result.Group == nil || result.APIKey.GroupID == nil || *result.APIKey.GroupID != result.Group.ID {
		response.ErrorFrom(c, ErrControlPlaneUnavailable)
		return
	}
	result.APIKey.Group = result.Group
	response.Success(c, struct {
		APIKey                 *cloudflareAPIKeyDTO `json:"api_key"`
		AutoGrantedGroupAccess bool                 `json:"auto_granted_group_access"`
		GrantedGroupID         *cloudflareJSONID    `json:"granted_group_id,omitempty"`
		GrantedGroupName       string               `json:"granted_group_name,omitempty"`
	}{
		APIKey:                 newCloudflareAPIKeyDTO(result.APIKey),
		AutoGrantedGroupAccess: result.AutoGrantedGroupAccess,
		GrantedGroupID:         cloudflareIDPointer(result.GrantedGroupID),
		GrantedGroupName:       result.GrantedGroupName,
	})
}
