package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// JSONReporter appends newline-delimited findings to a file, or writes them to
// stdout when no path is set.
type JSONReporter struct {
	outputFile string

	// The pipeline publishes from a single goroutine, so this lock is never
	// contended there. It is here because the interface does not promise a
	// single caller, and the previous version had no lock at all: with a worker
	// pool appending concurrently, O_APPEND only keeps writes atomic up to
	// PIPE_BUF, and a multi-kilobyte document could interleave.
	mu sync.Mutex
}

func NewJSONReporter(cfg *config.Config) (*JSONReporter, error) {
	return &JSONReporter{outputFile: cfg.ReporterPath}, nil
}

func (r *JSONReporter) Report(_ context.Context, f *scanner.Finding) error {
	// One document per line rather than indented: the file is a stream that
	// something else consumes, and a pretty-printed record cannot be read back
	// line by line.
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.outputFile == "" {
		_, err := fmt.Println(string(b))
		return err
	}

	out, err := os.OpenFile(r.outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(append(b, '\n'))
	return err
}
