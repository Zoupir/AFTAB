package agenthttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type IdentityEngine interface {
	GetUserUUID(context.Context, string) (string, bool, error)
}

func (c LocalClient) GetUserUUID(ctx context.Context, id string) (string, bool, error) {
	if e := c.validate(); e != nil {
		return "", false, e
	}
	if len(id) != 36 || strings.ContainsAny(id, "/\\") {
		return "", false, errors.New("invalid account ID")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", "http://"+c.Addr+"/v1/users/"+id+"/identity", nil)
	if e != nil {
		return "", false, e
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, e := safeAgentClient(c.HTTP).Do(req)
	if e != nil {
		return "", false, errors.New("identity agent unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("identity agent HTTP %d", resp.StatusCode)
	}
	uuid, found, e := parseIdentity(resp.Body)
	if e != nil {
		return "", false, fmt.Errorf("invalid agent identity response: %w", e)
	}
	return uuid, found, nil
}
