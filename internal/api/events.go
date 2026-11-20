package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Hub fans out PostgreSQL NOTIFY events (channel yourcve_events, written by
// the matcher) to SSE clients of the matching user.
type Hub struct {
	Pool *pgxpool.Pool
	Log  *slog.Logger

	mu   sync.Mutex
	subs map[int64]map[chan []byte]struct{}
}

func NewHub(pool *pgxpool.Pool, log *slog.Logger) *Hub {
	return &Hub{Pool: pool, Log: log, subs: map[int64]map[chan []byte]struct{}{}}
}

func (h *Hub) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := h.listen(ctx); err != nil && ctx.Err() == nil {
			h.Log.Warn("event listener stopped, reconnecting", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (h *Hub) listen(ctx context.Context) error {
	conn, err := h.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN yourcve_events`); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var ev struct {
			UserID int64 `json:"user_id"`
		}
		if json.Unmarshal([]byte(n.Payload), &ev) != nil {
			continue
		}
		h.mu.Lock()
		for ch := range h.subs[ev.UserID] {
			select {
			case ch <- []byte(n.Payload):
			default: // slow client, drop
			}
		}
		h.mu.Unlock()
	}
}

func (h *Hub) subscribe(userID int64) chan []byte {
	ch := make(chan []byte, 16)
	h.mu.Lock()
	if h.subs[userID] == nil {
		h.subs[userID] = map[chan []byte]struct{}{}
	}
	h.subs[userID][ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) unsubscribe(userID int64, ch chan []byte) {
	h.mu.Lock()
	delete(h.subs[userID], ch)
	if len(h.subs[userID]) == 0 {
		delete(h.subs, userID)
	}
	h.mu.Unlock()
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	u := userFrom(r.Context())
	ch := s.Hub.subscribe(u.ID)
	defer s.Hub.unsubscribe(u.ID, ch)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	fmt.Fprint(w, "retry: 5000\n: connected\n\n")
	fl.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case msg := <-ch:
			var ev map[string]any
			_ = json.Unmarshal(msg, &ev)
			delete(ev, "user_id")
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: match\ndata: %s\n\n", b)
			fl.Flush()
		}
	}
}
