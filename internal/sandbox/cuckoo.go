package sandbox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// cuckoo talks to a Cuckoo Sandbox REST API.
//
//	POST /tasks/create/file      multipart "file"  -> {"task_id": 123}
//	GET  /tasks/view/{id}                          -> {"task": {"status": "..."}}
//	GET  /tasks/report/{id}                        -> {"info": {"score": 6.4}, ...}
//
// Auth is an optional bearer token; a Cuckoo behind no auth accepts the same
// requests without the header.
type cuckoo struct {
	token string
}

func (c *cuckoo) name() string { return "cuckoo" }

func (c *cuckoo) auth(r *http.Request) {
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func (c *cuckoo) submit(ctx context.Context, cl *http.Client, base, key string, body io.Reader) (string, error) {
	form, contentType, err := multipartFile("file", key, body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/tasks/create/file", form)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	c.auth(req)

	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	var out struct {
		TaskID int64 `json:"task_id"`
		// Cuckoo answers a duplicate submission with task_ids rather than
		// task_id when it has seen the sample before.
		TaskIDs []int64 `json:"task_ids"`
	}
	if err := decodeJSON(resp, &out); err != nil {
		return "", err
	}
	if out.TaskID == 0 && len(out.TaskIDs) > 0 {
		out.TaskID = out.TaskIDs[0]
	}
	if out.TaskID == 0 {
		return "", fmt.Errorf("cuckoo: no task id in response")
	}
	return fmt.Sprint(out.TaskID), nil
}

// cuckooTerminal are the states from which no report will ever arrive.
//
// Treated as done rather than retried: polling a failed analysis forever costs
// nothing but never ends, and the task would stay pending with no document —
// which downstream reads as "clean" rather than "never answered".
var cuckooTerminal = map[string]bool{
	"reported":          true,
	"failed_analysis":   true,
	"failed_reporting":  true,
	"failed_processing": true,
}

func (c *cuckoo) status(ctx context.Context, cl *http.Client, base, token string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(base, "/")+"/tasks/view/"+token, nil)
	if err != nil {
		return "", false, err
	}
	c.auth(req)

	resp, err := cl.Do(req)
	if err != nil {
		return "", false, err
	}
	var out struct {
		Task struct {
			Status string `json:"status"`
		} `json:"task"`
	}
	if err := decodeJSON(resp, &out); err != nil {
		return "", false, err
	}
	return out.Task.Status, cuckooTerminal[out.Task.Status], nil
}

func (c *cuckoo) report(ctx context.Context, cl *http.Client, base, token string) (float64, map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(base, "/")+"/tasks/report/"+token, nil)
	if err != nil {
		return 0, nil, err
	}
	c.auth(req)

	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	// Only the fields worth publishing are decoded. A Cuckoo report is tens of
	// megabytes of behavioural trace, and storing it in Elasticsearch would be
	// both useless to query and a mapping explosion.
	var out struct {
		Info struct {
			Score    float64 `json:"score"`
			Category string  `json:"category"`
		} `json:"info"`
		Malscore   float64 `json:"malscore"`
		Signatures []struct {
			Name        string `json:"name"`
			Severity    int    `json:"severity"`
			Description string `json:"description"`
		} `json:"signatures"`
	}
	if err := decodeJSON(resp, &out); err != nil {
		return 0, nil, err
	}

	score := out.Info.Score
	if score == 0 && out.Malscore > 0 {
		score = out.Malscore
	}

	// Capped: a heavily-instrumented sample can trigger hundreds of signatures,
	// and the whole list adds size without adding meaning to a verdict.
	const maxSignatures = 20
	names := make([]string, 0, maxSignatures)
	for _, s := range out.Signatures {
		if len(names) == maxSignatures {
			break
		}
		names = append(names, s.Name)
	}

	return score, map[string]any{
		"signatures":      names,
		"signature_count": len(out.Signatures),
		"category":        out.Info.Category,
	}, nil
}
