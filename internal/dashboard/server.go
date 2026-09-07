package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/luhtaf/s3nitor/internal/db"
)

//go:embed ui
var uiFS embed.FS

// Server exposes the read-only API and the UI.
//
// Every route is a GET. There is no write path at all — not a disabled one, not
// one behind a flag — so a dashboard reachable by more people than the scanner
// cannot become a way to change anything.
type Server struct {
	es *ES
	// gdb is optional. Queue depth lives in the scanner's ledger rather than in
	// Elasticsearch, since the ledger deliberately stores no results; without a
	// database the queue panel simply reports that it is unavailable.
	gdb *gorm.DB
}

func NewServer(es *ES, gdb *gorm.DB) *Server { return &Server{es: es, gdb: gdb} }

// Routes wires the handlers.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/findings", s.handleFindings)
	mux.HandleFunc("GET /api/trends", s.handleTrends)
	mux.HandleFunc("GET /api/coverage", s.handleCoverage)
	mux.HandleFunc("GET /api/queue", s.handleQueue)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		log.Fatalf("embedded UI: %v", err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	return logging(mux)
}

// filtersFrom reads the shared filter set from the query string, so every
// endpoint interprets the same parameters identically.
func filtersFrom(r *http.Request) filters {
	q := r.URL.Query()
	return filters{
		Query:    q.Get("q"),
		Scanner:  q.Get("scanner"),
		Severity: q.Get("severity"),
		Match:    q.Get("match"),
		Since:    q.Get("since"),
	}
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	out, err := s.es.Summarise(r.Context(), filtersFrom(r))
	respond(w, out, err)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, _ := strconv.Atoi(q.Get("from"))
	size, _ := strconv.Atoi(q.Get("size"))
	out, err := s.es.Findings(r.Context(), filtersFrom(r), q.Get("sort"), q.Get("order"), from, size)
	respond(w, out, err)
}

func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	out, err := s.es.Trends(r.Context(), filtersFrom(r), r.URL.Query().Get("interval"))
	respond(w, out, err)
}

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := s.es.Coverage(r.Context(), limit)
	respond(w, out, err)
}

// QueueRow is one scanner's backlog.
type QueueRow struct {
	Scanner string `json:"scanner"`
	Status  string `json:"status"`
	Count   int64  `json:"count"`
	Oldest  string `json:"oldest,omitempty"`
}

// QueueView answers "what has not been done yet", which Elasticsearch cannot:
// findings only exist for work that finished.
type QueueView struct {
	Available bool       `json:"available"`
	Reason    string     `json:"reason,omitempty"`
	Rows      []QueueRow `json:"rows"`
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	if s.gdb == nil {
		respond(w, QueueView{
			Available: false,
			Reason:    "no DB_DSN configured; the queue lives in the scanner's ledger, not in Elasticsearch",
			Rows:      []QueueRow{},
		}, nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var rows []QueueRow
	err := s.gdb.WithContext(ctx).
		Model(&db.ScanTask{}).
		Select("scanner, status, count(*) as count, min(next_attempt_at) as oldest").
		Group("scanner, status").
		Order("scanner, status").
		Scan(&rows).Error
	if rows == nil {
		rows = []QueueRow{}
	}
	respond(w, QueueView{Available: err == nil, Rows: rows}, err)
}

func respond(w http.ResponseWriter, body any, err error) {
	w.Header().Set("Content-Type", "application/json")
	// The dashboard is read-only and served alongside the data it reads, so
	// nothing here is cacheable — a stale finding count is worse than a slow one.
	w.Header().Set("Cache-Control", "no-store")

	if err != nil {
		log.Printf("dashboard: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		// The upstream message is passed through: "index_not_found" or "missing
		// privilege" is exactly what the operator needs, and this endpoint is
		// not public.
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

// logging records each request without its query string, which carries the
// search terms an operator typed.
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

// ErrNoIndex is returned when the findings index does not exist yet.
var ErrNoIndex = errors.New("findings index does not exist yet")
