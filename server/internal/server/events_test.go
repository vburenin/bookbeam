package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEventsReachOnlyTheRightUser(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	phone := h.client().login("vlad", "test")
	car := h.client()
	car.ua = teslaUA
	car.login("vlad", "test")
	kid := h.client().login("kid", "test2")

	phoneEv := phone.openEvents("phone-tab")
	carEv := car.openEvents("car-tab")
	kidEv := kid.openEvents("kid-tab")

	lev := h.book("Expanse/Leviathan Wakes")
	// The car starts playing: the phone is told (and must pause); the car
	// does not get its own echo; the kid hears nothing.
	expectStatus(t, car.do("PUT", "/api/progress/"+lev.ID, map[string]any{
		"trackIndex": 0, "position": 5, "playing": true, "clientId": "car-tab", "event": "play",
	}), 200)
	ev := phoneEv.next(t)
	var playing map[string]string
	if err := json.Unmarshal([]byte(ev.data), &playing); err != nil || ev.name != "playing" ||
		playing["clientId"] != "car-tab" || playing["bookId"] != lev.ID || playing["deviceName"] != "Tesla" {
		t.Fatalf("playing event = %+v", ev)
	}
	ev = phoneEv.next(t)
	var prog progressEvent
	if err := json.Unmarshal([]byte(ev.data), &prog); err != nil || ev.name != "progress" ||
		prog.BookID != lev.ID || prog.ClientID != "car-tab" || prog.Progress == nil || prog.Progress.Position != 5 {
		t.Fatalf("progress event = %+v", ev)
	}
	carEv.expectNone(t)
	kidEv.expectNone(t)

	// A fresh stream learns who is playing from "hello".
	if hello := phone.openEvents("laptop-tab").hello; !strings.Contains(hello.data, `"activeClient":"car-tab"`) {
		t.Fatalf("hello = %+v", hello)
	}

	// Settings and bookmarks go to all of the user's streams except the
	// originating tab.
	expectStatus(t, phone.do("PATCH", "/api/settings?clientId=phone-tab", map[string]any{"theme": "light"}), 200)
	if ev := carEv.next(t); ev.name != "settings" || !strings.Contains(ev.data, `"theme":"light"`) {
		t.Fatalf("settings event = %+v", ev)
	}
	phoneEv.expectNone(t)
	expectStatus(t, phone.do("POST", "/api/books/"+lev.ID+"/bookmarks", map[string]any{"trackIndex": 0, "position": 1, "clientId": "phone-tab"}), 201)
	if ev := carEv.next(t); ev.name != "bookmarks" || !strings.Contains(ev.data, lev.ID) {
		t.Fatalf("bookmarks event = %+v", ev)
	}
	expectStatus(t, phone.do("DELETE", "/api/progress/"+lev.ID+"?clientId=phone-tab", nil), 200)
	if ev := carEv.next(t); ev.name != "progress" || !strings.Contains(ev.data, `"progress":null`) {
		t.Fatalf("delete progress event = %+v", ev)
	}
	phoneEv.expectNone(t)
	kidEv.expectNone(t)

	// Library events go to everyone.
	expectStatus(t, kid.do("POST", "/api/library/rescan", nil), 202)
	for _, s := range []*sseStream{phoneEv, carEv, kidEv} {
		if ev := s.next(t); ev.name != "library" {
			t.Fatalf("library event = %+v", ev)
		}
	}
}

func TestEventsClosedOnShutdown(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	s := h.client().login("vlad", "test").openEvents("tab")
	h.srv.CloseStreams()
	s.expectClosed(t)
	expectStatus(t, h.client().login("vlad", "test").do("GET", "/api/events", nil), 503)
}
