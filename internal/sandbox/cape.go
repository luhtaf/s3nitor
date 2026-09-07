package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// cape talks to a CAPEv2 REST API.
//
//	POST /apiv2/tasks/create/file/        multipart "file"
//	     -> {"error": false, "data": {"task_ids": [123]}}
//	GET  /apiv2/tasks/status/{id}/        -> {"error": false, "data": "reported"}
//	GET  /apiv2/tasks/get/report/{id}/    -> {"malscore": 6.4, ...}
//
// Three differences from Cuckoo that all have to be right at once, which is why
// this is a separate type rather than a flag on one client:
//
//  1. every path is under /apiv2/ and carries a trailing slash — CAPE redirects
//     without it, and a redirected POST silently loses its body;
//  2. auth is "Token <key>", not "Bearer <key>";
//  3. responses are wrapped in {"error":…, "data":…}, and an error is reported
//     with HTTP 200, so the status code alone never reveals a failure.
type cape struct {
	token string
}

func (c *cape) name() string { return "cape" }

func (c *cape) auth(r *http.Request) {
	if c.token != "" {
		r.Header.Set("Authorization", "Token "+c.token)
	}
}

// capeEnvelope is the wrapper around every CAPE response.
//
// Data is deferred rather than typed because it is a string for status and an
// object for submission — decoding it eagerly would need two envelopes.
type capeEnvelope struct {
	Error   bool            `json:"error"`
	Message string          `json:"error_value"`
	Data    json.RawMessage `json:"data"`
}

// check surfaces an in-band error that arrived with HTTP 200.
func (e capeEnvelope) check() error {
	if e.Error {
		msg := e.Message
		if msg == "" {
			msg = "unspecified"
		}
		return fmt.Errorf("cape: %s", msg)
	}
	return nil
}

func (c *cape) submit(ctx context.Context, cl *http.Client, base, key string, body io.Reader) (string, error) {
	form, contentType, err := multipartFile("file", key, body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/apiv2/tasks/create/file/", form)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	c.auth(req)

	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	var env capeEnvelope
	if err := decodeJSON(resp, &env); err != nil {
		return "", err
	}
	if err := env.check(); err != nil {
		return "", err
	}
	var data struct {
		TaskIDs []int64 `json:"task_ids"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return "", fmt.Errorf("cape: decoding submit data: %w", err)
	}
	if len(data.TaskIDs) == 0 {
		return "", fmt.Errorf("cape: no task id in response")
	}
	// One id even when CAPE fans a submission across several analyses: the
	// document is per (file x scanner), so a second id would have nowhere to go.
	return fmt.Sprint(data.TaskIDs[0]), nil
}

// capeTerminal are the states from which no report will ever arrive.
var capeTerminal = map[string]bool{
	"reported":          true,
	"failed_analysis":   true,
	"failed_processing": true,
	"failed_reporting":  true,
}

func (c *cape) status(ctx context.Context, cl *http.Client, base, token string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(base, "/")+"/apiv2/tasks/status/"+token+"/", nil)
	if err != nil {
		return "", false, err
	}
	c.auth(req)

	resp, err := cl.Do(req)
	if err != nil {
		return "", false, err
	}
	var env capeEnvelope
	if err := decodeJSON(resp, &env); err != nil {
		return "", false, err
	}
	if err := env.check(); err != nil {
		return "", false, err
	}
	var state string
	if err := json.Unmarshal(env.Data, &state); err != nil {
		return "", false, fmt.Errorf("cape: decoding status: %w", err)
	}
	return state, capeTerminal[state], nil
}

func (c *cape) report(ctx context.Context, cl *http.Client, base, token string) (float64, map[string]any, error) {
	// The json subset, not the full report: CAPE's complete report runs to
	// hundreds of megabytes of behavioural trace, which is neither useful in
	// Elasticsearch nor safe to hold in memory here.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(base, "/")+"/apiv2/tasks/get/report/"+token+"/json/", nil)
	if err != nil {
		return 0, nil, err
	}
	c.auth(req)

	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var out struct {
		Malscore float64 `json:"malscore"`
		Info     struct {
			Score    float64 `json:"score"`
			Category string  `json:"category"`
		} `json:"info"`
		Detections []struct {
			Family string `json:"family"`
		} `json:"detections"`
		Signatures []struct {
			Name     string `json:"name"`
			Severity int    `json:"severity"`
		} `json:"signatures"`
	}
	if err := decodeJSON(resp, &out); err != nil {
		return 0, nil, err
	}

	score := out.Malscore
	if score == 0 && out.Info.Score > 0 {
		score = out.Info.Score
	}

	const maxSignatures = 20
	names := make([]string, 0, maxSignatures)
	for _, s := range out.Signatures {
		if len(names) == maxSignatures {
			break
		}
		names = append(names, s.Name)
	}
	families := make([]string, 0, len(out.Detections))
	for _, d := range out.Detections {
		if d.Family != "" {
			families = append(families, d.Family)
		}
	}

	return score, map[string]any{
		"signatures":      names,
		"signature_count": len(out.Signatures),
		"families":        families,
		"category":        out.Info.Category,
	}, nil
}
