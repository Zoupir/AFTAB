package agenthttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type LocalClient struct {
	Addr  string
	Token string
	HTTP  *http.Client
}

func (c LocalClient) validate() error {
	if !Loopback(c.Addr) || len(c.Token) < 32 || len(c.Token) > 512 {
		return errors.New("invalid local agent settings")
	}
	return nil
}
func (c LocalClient) post(ctx context.Context, path string, payload any) error {
	if e := c.validate(); e != nil {
		return e
	}
	var data []byte
	if payload != nil {
		data, _ = json.Marshal(payload)
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "http://"+c.Addr+path, bytes.NewReader(data))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, e := safeAgentClient(c.HTTP).Do(req)
	if e != nil {
		return errors.New("agent_connection_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("agent_rejected_operation_http_%d", resp.StatusCode)
	}
	expected := "provisioned"
	if strings.HasSuffix(path, "/disable") {
		expected = "removed"
	}
	if e := parseAck(resp.Body, expected); e != nil {
		return fmt.Errorf("agent ack invalid: %w", e)
	}
	return nil
}
func (c LocalClient) AddUser(ctx context.Context, id, uuid string) error {
	return c.post(ctx, "/v1/users", map[string]string{"id": id, "uuid": uuid})
}
func (c LocalClient) RemoveUser(ctx context.Context, id string) error {
	if strings.ContainsAny(id, "/\\") || len(id) != 36 {
		return errors.New("invalid id")
	}
	return c.post(ctx, "/v1/users/"+id+"/disable", nil)
}
func ValidateLocalClient(c LocalClient) error { return c.validate() }
