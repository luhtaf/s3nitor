package dashboard

import (
	"context"
	"sort"
)

// Summary is the headline: what has been scanned and what came back.
type Summary struct {
	Objects    int            `json:"objects"`  // distinct objects, not findings
	Findings   int            `json:"findings"` // one per (object × scanner)
	Matches    int            `json:"matches"`  // findings that detected something
	Errors     int            `json:"errors"`   // scanners that failed to run
	Gaps       int            `json:"gaps"`     // objects deliberately not scanned
	BySeverity map[string]int `json:"by_severity"`
	ByScanner  map[string]int `json:"by_scanner"`
	LastScan   string         `json:"last_scan"`
}

// Summarise counts in one round trip.
//
// Distinct objects come from a cardinality aggregation on file_id rather than
// from the document count: several findings share an object, so counting
// documents would report scanning far more than actually happened.
func (e *ES) Summarise(ctx context.Context, f filters) (*Summary, error) {
	res, err := e.search(ctx, map[string]any{
		"size":  0,
		"query": f.query(),
		"aggs": map[string]any{
			"objects":  map[string]any{"cardinality": map[string]any{"field": "file_id"}},
			"matches":  map[string]any{"filter": map[string]any{"term": map[string]any{"match": true}}},
			"errors":   map[string]any{"filter": map[string]any{"exists": map[string]any{"field": "error"}}},
			"gaps":     map[string]any{"filter": map[string]any{"term": map[string]any{"scanner": "size_gate"}}},
			"severity": map[string]any{"terms": map[string]any{"field": "severity", "size": 10}},
			"scanner":  map[string]any{"terms": map[string]any{"field": "scanner", "size": 20}},
			"last":     map[string]any{"max": map[string]any{"field": "scanned_at"}},
		},
	})
	if err != nil {
		return nil, err
	}

	s := &Summary{BySeverity: map[string]int{}, ByScanner: map[string]int{}}
	s.Findings = num(dig(res, "hits", "total", "value"))
	s.Objects = num(dig(res, "aggregations", "objects", "value"))
	s.Matches = num(dig(res, "aggregations", "matches", "doc_count"))
	s.Errors = num(dig(res, "aggregations", "errors", "doc_count"))
	s.Gaps = num(dig(res, "aggregations", "gaps", "doc_count"))

	for _, b := range buckets(dig(res, "aggregations", "severity", "buckets")) {
		if key, ok := b["key"].(string); ok {
			s.BySeverity[key] = num(b["doc_count"])
		}
	}
	for _, b := range buckets(dig(res, "aggregations", "scanner", "buckets")) {
		if key, ok := b["key"].(string); ok {
			s.ByScanner[key] = num(b["doc_count"])
		}
	}
	if v, ok := dig(res, "aggregations", "last", "value_as_string").(string); ok {
		s.LastScan = v
	}
	return s, nil
}

// Finding is one row in the table.
type Finding struct {
	FileID    string         `json:"file_id"`
	Bucket    string         `json:"bucket"`
	Key       string         `json:"key"`
	Size      int64          `json:"size"`
	Scanner   string         `json:"scanner"`
	Match     bool           `json:"match"`
	Severity  string         `json:"severity"`
	Detail    map[string]any `json:"detail,omitempty"`
	Hashes    map[string]any `json:"hashes,omitempty"`
	ScannedAt string         `json:"scanned_at"`
	Error     string         `json:"error,omitempty"`
}

// Page is a slice of the table plus the total, so the UI can paginate.
type Page struct {
	Total int        `json:"total"`
	Items []*Finding `json:"items"`
}

var sortableFields = map[string]bool{
	"scanned_at": true, "severity": true, "size": true,
	"key": true, "scanner": true, "match": true,
}

// Findings returns one page of the table.
func (e *ES) Findings(ctx context.Context, f filters, sortBy, order string, from, size int) (*Page, error) {
	if !sortableFields[sortBy] {
		sortBy = "scanned_at"
	}
	if order != "asc" {
		order = "desc"
	}
	if size <= 0 || size > 200 {
		size = 50
	}

	res, err := e.search(ctx, map[string]any{
		"from":  from,
		"size":  size,
		"query": f.query(),
		"sort":  []any{map[string]any{sortBy: map[string]any{"order": order}}},
		// track_total_hits so the pager shows a real count rather than
		// Elasticsearch's default 10 000 ceiling.
		"track_total_hits": true,
	})
	if err != nil {
		return nil, err
	}

	page := &Page{Items: []*Finding{}}
	page.Total = num(dig(res, "hits", "total", "value"))

	for _, h := range buckets(dig(res, "hits", "hits")) {
		src, ok := h["_source"].(map[string]any)
		if !ok {
			continue
		}
		fi := &Finding{}
		fi.FileID, _ = src["file_id"].(string)
		fi.Bucket, _ = src["bucket"].(string)
		fi.Key, _ = src["key"].(string)
		fi.Scanner, _ = src["scanner"].(string)
		fi.Severity, _ = src["severity"].(string)
		fi.ScannedAt, _ = src["scanned_at"].(string)
		fi.Error, _ = src["error"].(string)
		fi.Match, _ = src["match"].(bool)
		if v, ok := src["size"].(float64); ok {
			fi.Size = int64(v)
		}
		fi.Detail, _ = src["detail"].(map[string]any)
		fi.Hashes, _ = src["hashes"].(map[string]any)
		page.Items = append(page.Items, fi)
	}
	return page, nil
}

// TrendBucket is one interval on the time axis.
type TrendBucket struct {
	Time       string         `json:"time"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

// Trends returns findings over time, split by severity.
//
// Split by severity rather than by scanner: the question a trend answers here is
// "is it getting worse", and severity is the axis that carries that.
func (e *ES) Trends(ctx context.Context, f filters, interval string) ([]TrendBucket, error) {
	switch interval {
	case "hour", "day", "minute", "week":
	default:
		interval = "hour"
	}

	res, err := e.search(ctx, map[string]any{
		"size":  0,
		"query": f.query(),
		"aggs": map[string]any{
			"over_time": map[string]any{
				"date_histogram": map[string]any{
					"field":             "scanned_at",
					"calendar_interval": interval,
					// Empty intervals are returned so a quiet period reads as a
					// gap in the line rather than as two adjacent points joined
					// across it.
					"min_doc_count": 0,
				},
				"aggs": map[string]any{
					"severity": map[string]any{"terms": map[string]any{"field": "severity", "size": 10}},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	out := []TrendBucket{}
	for _, b := range buckets(dig(res, "aggregations", "over_time", "buckets")) {
		tb := TrendBucket{Total: num(b["doc_count"]), BySeverity: map[string]int{}}
		tb.Time, _ = b["key_as_string"].(string)
		for _, sb := range buckets(dig(b, "severity", "buckets")) {
			if key, ok := sb["key"].(string); ok {
				tb.BySeverity[key] = num(sb["doc_count"])
			}
		}
		out = append(out, tb)
	}
	return out, nil
}

// Gap is an object that was deliberately not scanned.
type Gap struct {
	Key       string `json:"key"`
	Bucket    string `json:"bucket"`
	Size      int64  `json:"size"`
	Reason    string `json:"reason"`
	Limit     int64  `json:"limit"`
	ScannedAt string `json:"scanned_at"`
}

// Coverage lists what the scanner chose to skip.
//
// The most useful thing on the page and the easiest to leave out: a scanner that
// silently declines to look at the largest objects in a bucket is worse than one
// that reports nothing, because it looks like it worked.
func (e *ES) Coverage(ctx context.Context, limit int) ([]Gap, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	res, err := e.search(ctx, map[string]any{
		"size": limit,
		"query": map[string]any{
			"term": map[string]any{"scanner": "size_gate"},
		},
		"sort": []any{map[string]any{"size": map[string]any{"order": "desc"}}},
	})
	if err != nil {
		return nil, err
	}

	out := []Gap{}
	for _, h := range buckets(dig(res, "hits", "hits")) {
		src, ok := h["_source"].(map[string]any)
		if !ok {
			continue
		}
		g := Gap{}
		g.Key, _ = src["key"].(string)
		g.Bucket, _ = src["bucket"].(string)
		g.ScannedAt, _ = src["scanned_at"].(string)
		if v, ok := src["size"].(float64); ok {
			g.Size = int64(v)
		}
		if d, ok := src["detail"].(map[string]any); ok {
			g.Reason, _ = d["reason"].(string)
			if v, ok := d["limit"].(float64); ok {
				g.Limit = int64(v)
			}
		}
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Size > out[j].Size })
	return out, nil
}
