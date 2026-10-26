package agenthttp

// The panel uses this query to verify recovery and revocation against live
// Xray state, instead of treating an accepted write as proof of its effect.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 7 * time.Second}
	}
	resp, e := client.Do(req)
	if e != nil {
		return "", false, errors.New("identity agent unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("identity agent HTTP %d", resp.StatusCode)
	}
	var payload struct {
		UUID  string `json:"uuid"`
		Found bool   `json:"found"`
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	d.DisallowUnknownFields()
	if e := d.Decode(&payload); e != nil {
		return "", false, e
	}
	if payload.Found && len(payload.UUID) != 36 {
		return "", false, errors.New("invalid engine identity response")
	}
	return payload.UUID, payload.Found, nil
}
