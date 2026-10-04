package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/vburenin/bookbeam/server/internal/auth"
)

const (
	ssePingInterval = 20 * time.Second
	// sseBuffer is how many events may queue for a slow client before it
	// is disconnected (it reconnects and resynchronises).
	sseBuffer = 64
)

type sseMsg struct {
	event string
	data  []byte
}

// subscriber is one open event stream.
type subscriber struct {
	user    string
	session string
	client  string
	ch      chan sseMsg
	done    chan struct{}
	once    sync.Once
	final   *sseMsg // written before done is closed
}

// kick ends the stream, optionally after one last event.
func (s *subscriber) kick(final *sseMsg) {
	s.once.Do(func() {
		s.final = final
		close(s.done)
	})
}

// hub fans events out to the open streams. Events are only ever delivered
// to streams of the user they concern.
type hub struct {
	mu     sync.Mutex
	subs   map[*subscriber]struct{}
	closed bool
}

func newHub() *hub { return &hub{subs: map[*subscriber]struct{}{}} }

func (h *hub) subscribe(user, session, client string) (*subscriber, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, false
	}
	s := &subscriber{user: user, session: session, client: client,
		ch: make(chan sseMsg, sseBuffer), done: make(chan struct{})}
	h.subs[s] = struct{}{}
	return s, true
}

func (h *hub) unsubscribe(s *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, s)
}

// publish sends an event to user's streams, except those of exceptClient.
func (h *hub) publish(user, exceptClient, event string, payload any) {
	h.send(event, payload, func(s *subscriber) bool {
		return s.user == user && (exceptClient == "" || s.client != exceptClient)
	})
}

// publishAll sends an event to every stream.
func (h *hub) publishAll(event string, payload any) {
	h.send(event, payload, func(*subscriber) bool { return true })
}

func (h *hub) send(event string, payload any, match func(*subscriber) bool) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := sseMsg{event: event, data: data}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if !match(s) {
			continue
		}
		select {
		case s.ch <- msg:
		default:
			s.kick(nil) // too slow; it will reconnect and refetch
		}
	}
}

// closeSession ends the streams of a revoked session.
func (h *hub) closeSession(session string) {
	final := &sseMsg{event: "session-revoked", data: []byte("{}")}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.session == session {
			s.kick(final)
		}
	}
}

// close ends all streams and refuses new ones (server shutdown).
func (h *hub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for s := range h.subs {
		s.kick(nil)
	}
}

// handleEvents serves GET api/events as Server-Sent Events.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	clientID := r.URL.Query().Get("clientId")
	if len(clientID) > 64 {
		clientID = clientID[:64]
	}
	sub, ok := s.hub.subscribe(sess.User, sess.ID, clientID)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "server is shutting down")
		return
	}
	defer s.hub.unsubscribe(sub)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)

	write := func(m sseMsg) bool {
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m.event, m.data); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	hello, _ := json.Marshal(map[string]any{
		"serverTime":   time.Now().UnixMilli(),
		"activeClient": s.store.ActiveClient(sess.User),
	})
	if !write(sseMsg{event: "hello", data: hello}) {
		return
	}

	ping := time.NewTicker(ssePingInterval)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.done:
			if sub.final != nil {
				write(*sub.final)
			}
			return
		case m := <-sub.ch:
			if !write(m) {
				return
			}
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}
