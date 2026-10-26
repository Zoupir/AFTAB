package agenthttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

const agentResponseLimit = 4096

var canonicalUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// safeAgentClient never follows redirects on a bearer-authenticated local
// request, even when the caller provided a configured HTTP client.
func safeAgentClient(existing *http.Client) *http.Client {
	if existing == nil {
		existing = &http.Client{Timeout: 7 * time.Second}
	}
	clone := *existing
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}

// readAgentFields prevents silent zero values from missing JSON members,
// duplicate keys, unknown fields, trailing documents or oversized replies.
func readAgentFields(body io.Reader, fields ...string) (map[string]json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(body, agentResponseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("agent response read: %w", err)
	}
	if len(data) > agentResponseLimit {
		return nil, errors.New("agent response too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("agent response must be JSON object")
	}
	allowed := make(map[string]bool, len(fields))
	for _, f := range fields {
		allowed[f] = true
	}
	actual := make(map[string]json.RawMessage, len(fields))
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, errors.New("malformed agent JSON key")
		}
		name, ok := key.(string)
		if !ok || !allowed[name] {
			return nil, errors.New("unknown agent response field")
		}
		if _, exists := actual[name]; exists {
			return nil, errors.New("duplicate agent response field")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, errors.New("invalid agent response value")
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, errors.New("null agent response value")
		}
		actual[name] = raw
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("invalid agent response end")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing agent response content")
	}
	for _, key := range fields {
		if _, ok := actual[key]; !ok {
			return nil, fmt.Errorf("missing agent response field %q", key)
		}
	}
	return actual, nil
}

func parseTraffic(body io.Reader) (uplink, downlink int64, err error) {
	fields, err := readAgentFields(body, "uplink", "downlink")
	if err != nil {
		return 0, 0, err
	}
	if err = json.Unmarshal(fields["uplink"], &uplink); err != nil {
		return 0, 0, errors.New("invalid uplink value")
	}
	if err = json.Unmarshal(fields["downlink"], &downlink); err != nil {
		return 0, 0, errors.New("invalid downlink value")
	}
	if uplink < 0 || downlink < 0 {
		return 0, 0, errors.New("negative traffic counter")
	}
	return uplink, downlink, nil
}

func parseIdentity(body io.Reader) (uuid string, found bool, err error) {
	fields, err := readAgentFields(body, "found", "uuid")
	if err != nil {
		return "", false, err
	}
	if err = json.Unmarshal(fields["found"], &found); err != nil {
		return "", false, errors.New("invalid found type")
	}
	if err = json.Unmarshal(fields["uuid"], &uuid); err != nil {
		return "", false, errors.New("invalid uuid type")
	}
	if found && !canonicalUUID.MatchString(uuid) {
		return "", false, errors.New("invalid found UUID")
	}
	if !found && uuid != "" {
		return "", false, errors.New("absent user unexpectedly has UUID")
	}
	return uuid, found, nil
}

func parseAck(body io.Reader, expected string) error {
	fields, err := readAgentFields(body, "status")
	if err != nil {
		return err
	}
	var state string
	if err = json.Unmarshal(fields["status"], &state); err != nil || state != expected {
		return errors.New("unexpected agent acknowledgment")
	}
	return nil
}
