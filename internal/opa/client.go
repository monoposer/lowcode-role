package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func New(base string) *Client {
	return &Client{
		BaseURL: base,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        128,
				MaxIdleConnsPerHost: 128,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

type evalRequest struct {
	Input json.RawMessage `json:"input"`
}

// EvalAllow calls OPA data.authz.allow with the given input document.
func (c *Client) EvalAllow(ctx context.Context, input any) (bool, time.Duration, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return false, 0, err
	}
	payload, err := json.Marshal(evalRequest{Input: raw})
	if err != nil {
		return false, 0, err
	}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/data/authz/allow", bytes.NewReader(payload))
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	d := time.Since(start)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, d, fmt.Errorf("opa status %d: %s", resp.StatusCode, string(body))
	}
	var outer struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &outer); err != nil {
		return false, d, fmt.Errorf("decode opa: %w", err)
	}
	ok, err := decodeBoolish(outer.Result)
	return ok, d, err
}

func decodeBoolish(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var arr []bool
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, x := range arr {
			if x {
				return true, nil
			}
		}
		return false, nil
	}
	// set-like [true] or objects — treat any truthy JSON true as allow
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return false, err
	}
	switch v := generic.(type) {
	case bool:
		return v, nil
	case []interface{}:
		for _, e := range v {
			if e == true {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("unexpected opa result: %s", string(raw))
	}
}
