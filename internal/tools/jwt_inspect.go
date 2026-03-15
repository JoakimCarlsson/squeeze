package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

type JWTInspectParams struct {
	Token       string `json:"token"                   description:"The JWT to decode and analyse"`
	TestAlgNone bool   `json:"test_alg_none,omitempty" description:"Forge a token with alg:none and an empty signature to test whether the server enforces algorithm verification"`
}

type JWTInspectTool struct{}

func NewJWTInspect() *JWTInspectTool {
	return &JWTInspectTool{}
}

func (t *JWTInspectTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"jwt_inspect",
		`Decode a JWT without verification and return its header, payload, and expiry status.
Optionally test for the alg:none vulnerability by producing a forged token with no signature.
Use this when you find JWTs in cookies, Authorization headers, or API responses.
Does not verify signatures — use this for analysis, not validation.`,
		JWTInspectParams{},
	)
}

func (t *JWTInspectTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[JWTInspectParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Token == "" {
		return tool.NewTextErrorResponse("token is required"), nil
	}

	raw := strings.TrimSpace(strings.TrimPrefix(input.Token, "Bearer "))

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return tool.NewTextErrorResponse("invalid JWT: expected 3 dot-separated parts"), nil
	}

	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("failed to decode header: %v", err)), nil
	}

	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("failed to decode payload: %v", err)), nil
	}

	expired := false
	if exp, ok := payload["exp"]; ok {
		if v, ok := exp.(float64); ok {
			expired = time.Now().Unix() > int64(v)
		}
	}

	type result struct {
		Header            map[string]any `json:"header"`
		Payload           map[string]any `json:"payload"`
		Expired           bool           `json:"expired"`
		AlgNoneVulnerable bool           `json:"alg_none_vulnerable,omitempty"`
		ForgedToken       string         `json:"forged_token,omitempty"`
	}

	res := result{
		Header:  header,
		Payload: payload,
		Expired: expired,
	}

	if input.TestAlgNone {
		noneHeader := map[string]any{"alg": "none", "typ": "JWT"}
		noneHeaderJSON, err := json.Marshal(noneHeader)
		if err != nil {
			return tool.NewTextErrorResponse(fmt.Sprintf("failed to marshal alg:none header: %v", err)), nil
		}
		res.AlgNoneVulnerable = true
		res.ForgedToken = base64.RawURLEncoding.EncodeToString(noneHeaderJSON) + "." + parts[1] + "."
	}

	return tool.NewJSONResponse(res), nil
}

func decodeJWTPart(s string) (map[string]any, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}
	return out, nil
}
