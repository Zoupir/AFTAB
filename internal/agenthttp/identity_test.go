package agenthttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeIdentityEngine struct{}

func (fakeIdentityEngine) AddUser(context.Context, string, string) error { return nil }
func (fakeIdentityEngine) RemoveUser(context.Context, string) error      { return nil }
func (fakeIdentityEngine) GetUserUUID(_ context.Context, id string) (string, bool, error) {
	if id == "1a5bc922-c418-4985-a4da-8ce4de68f725" {
		return "872e14a6-1433-4753-b8cb-f194629e158a", true, nil
	}
	return "", false, nil
}
func TestAgentIdentityQueryIsAuthenticated(t *testing.T) {
	secret := strings.Repeat("K", 64)
	server := httptest.NewServer(&Handler{Token: secret, Engine: fakeIdentityEngine{}})
	defer server.Close()
	client := LocalClient{Addr: strings.TrimPrefix(server.URL, "http://"), Token: secret}
	id := "1a5bc922-c418-4985-a4da-8ce4de68f725"
	uuid, found, e := client.GetUserUUID(context.Background(), id)
	if e != nil || !found || uuid != "872e14a6-1433-4753-b8cb-f194629e158a" {
		t.Fatalf("bad identity result %q %v %v", uuid, found, e)
	}
	_, found, e = client.GetUserUUID(context.Background(), "1a5bc922-c418-4985-a4da-8ce4de68f726")
	if e != nil || found {
		t.Fatal("unrecognized identity should be absent")
	}
	response, e := http.Get(server.URL + "/v1/users/" + id + "/identity")
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("unprotected identity response: HTTP %d", response.StatusCode)
	}
}
