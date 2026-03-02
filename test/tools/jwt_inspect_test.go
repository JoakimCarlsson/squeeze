package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	sqtools "github.com/joakimcarlsson/squeeze/internal/tools"
)

func makeJWT(headerJSON, payloadJSON string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return h + "." + p + ".fakesig"
}

func TestJWTInspect_Info(t *testing.T) {
	tool := sqtools.NewJWTInspect()
	info := tool.Info()
	if info.Name != "jwt_inspect" {
		t.Fatalf("expected name jwt_inspect, got %s", info.Name)
	}
}

func TestJWTInspect_Decode(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"user_123","iss":"api.example.com","exp":9999999999}`,
	)

	tool := sqtools.NewJWTInspect()
	resp, err := tool.Run(context.Background(), makeCall("jwt_inspect", `{"token":"`+token+`"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		Header  map[string]any `json:"header"`
		Payload map[string]any `json:"payload"`
		Expired bool           `json:"expired"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Header["alg"] != "HS256" {
		t.Errorf("expected header alg HS256, got %v", result.Header["alg"])
	}
	if result.Payload["sub"] != "user_123" {
		t.Errorf("expected payload sub user_123, got %v", result.Payload["sub"])
	}
	if result.Payload["iss"] != "api.example.com" {
		t.Errorf("expected payload iss api.example.com, got %v", result.Payload["iss"])
	}
	if result.Expired {
		t.Error("expected token to not be expired")
	}
}

func TestJWTInspect_Expired(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"old_user","exp":1}`,
	)

	tool := sqtools.NewJWTInspect()
	resp, err := tool.Run(context.Background(), makeCall("jwt_inspect", `{"token":"`+token+`"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		Expired bool `json:"expired"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if !result.Expired {
		t.Error("expected token to be expired")
	}
}

func TestJWTInspect_AlgNone(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"user_123","role":"user","exp":9999999999}`,
	)

	input := `{"token":"` + token + `","test_alg_none":true}`
	tool := sqtools.NewJWTInspect()
	resp, err := tool.Run(context.Background(), makeCall("jwt_inspect", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		AlgNoneVulnerable bool   `json:"alg_none_vulnerable"`
		ForgedToken       string `json:"forged_token"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if !result.AlgNoneVulnerable {
		t.Error("expected alg_none_vulnerable to be true")
	}
	if result.ForgedToken == "" {
		t.Fatal("expected forged_token to be populated")
	}
	if !strings.HasSuffix(result.ForgedToken, ".") {
		t.Errorf("forged token should end with empty signature (trailing '.'), got: %s", result.ForgedToken)
	}

	parts := strings.Split(result.ForgedToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in forged token, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode forged header: %v", err)
	}
	var forgedHeader map[string]any
	if err := json.Unmarshal(headerBytes, &forgedHeader); err != nil {
		t.Fatalf("failed to unmarshal forged header: %v", err)
	}
	if forgedHeader["alg"] != "none" {
		t.Errorf("expected forged header alg to be 'none', got %v", forgedHeader["alg"])
	}

	originalParts := strings.Split(token, ".")
	if parts[1] != originalParts[1] {
		t.Error("expected forged token payload to match original payload")
	}
}

func TestJWTInspect_BearerPrefix(t *testing.T) {
	token := makeJWT(
		`{"alg":"RS256","typ":"JWT"}`,
		`{"sub":"svc_account","exp":9999999999}`,
	)

	input := `{"token":"Bearer ` + token + `"}`
	tool := sqtools.NewJWTInspect()
	resp, err := tool.Run(context.Background(), makeCall("jwt_inspect", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		Header map[string]any `json:"header"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Header["alg"] != "RS256" {
		t.Errorf("expected alg RS256, got %v", result.Header["alg"])
	}
}

func TestJWTInspect_MissingToken(t *testing.T) {
	tool := sqtools.NewJWTInspect()
	resp, err := tool.Run(context.Background(), makeCall("jwt_inspect", `{"token":""}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected an error response for empty token")
	}
}

func TestJWTInspect_InvalidToken(t *testing.T) {
	tool := sqtools.NewJWTInspect()
	resp, err := tool.Run(context.Background(), makeCall("jwt_inspect", `{"token":"notajwt"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected an error response for malformed token")
	}
}
