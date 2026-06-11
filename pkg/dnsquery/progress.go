package dnsquery

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// progressRenderInterval is how often the in-place progress line is redrawn.
const progressRenderInterval = 200 * time.Millisecond

// clearLine moves the cursor to the start of the line and erases it.
const clearLine = "\r\x1b[K"

// progressTracker renders an in-place progress line for the benchmark run.
// A nil tracker is valid and all its methods are no-ops, so callers don't
// need to guard every call site.
type progressTracker struct {
	w       io.Writer
	total   int64
	done    atomic.Int64
	stopCh  chan struct{}
	stopped chan struct{}
}

// formatProgress builds the human-readable progress line.
func formatProgress(done, total int64) string {
	var pct int64
	if total > 0 {
		pct = done * 100 / total
	}
	return fmt.Sprintf("Benchmarking: %d/%d queries (%d%%)", done, total, pct)
}

// newProgressTracker creates a tracker writing to w and starts its render loop.
func newProgressTracker(w io.Writer, total int64) *progressTracker {
	p := &progressTracker{
		w:       w,
		total:   total,
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go p.renderLoop()
	return p
}

// increment records one completed (or skipped) query.
func (p *progressTracker) increment() {
	if p == nil {
		return
	}
	p.done.Add(1)
}

// renderLoop redraws the progress line until stop is called.
func (p *progressTracker) renderLoop() {
	defer close(p.stopped)
	ticker := time.NewTicker(progressRenderInterval)
	defer ticker.Stop()

	p.render()
	for {
		select {
		case <-ticker.C:
			p.render()
		case <-p.stopCh:
			// Render the final state, then erase the line so subsequent
			// output starts clean.
			p.render()
			_, _ = fmt.Fprint(p.w, clearLine)
			return
		}
	}
}

func (p *progressTracker) render() {
	_, _ = fmt.Fprint(p.w, clearLine+formatProgress(p.done.Load(), p.total))
}

// stop terminates the render loop and clears the progress line. Safe to call
// on a nil tracker; must be called at most once otherwise.
func (p *progressTracker) stop() {
	if p == nil {
		return
	}
	close(p.stopCh)
	<-p.stopped
}
