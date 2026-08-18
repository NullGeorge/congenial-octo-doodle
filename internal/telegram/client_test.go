package telegram

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "123456:AAHfake-token-value"

func TestSendMessage(t *testing.T) {
	var gotPath string
	var gotForm map[string][]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		gotForm = r.PostForm
		w.Write([]byte(`{"ok":true,"result":{"message_id":7}}`))
	}))
	defer server.Close()

	client := New(testToken, server.URL)
	if err := client.SendMessage(context.Background(), -1001234567890, "access granted"); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	if want := "/bot" + testToken + "/sendMessage"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if got := gotForm["chat_id"]; len(got) != 1 || got[0] != "-1001234567890" {
		t.Errorf("chat_id = %v, want -1001234567890", got)
	}
	if got := gotForm["text"]; len(got) != 1 || got[0] != "access granted" {
		t.Errorf("text = %v, want %q", got, "access granted")
	}
}

// The Bot API rejects anything past 4096 characters, so an over-long alert has
// to be clipped on a rune boundary rather than dropped or truncated by bytes.
func TestSendMessageTruncatesOnRuneBoundary(t *testing.T) {
	var gotText string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotText = r.PostForm.Get("text")
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer server.Close()

	// Cyrillic is two bytes per rune, so a byte slice would cut a rune apart.
	long := strings.Repeat("я", 5000)
	client := New(testToken, server.URL)
	if err := client.SendMessage(context.Background(), 1, long); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	runes := []rune(gotText)
	if len(runes) != messageLimit {
		t.Errorf("sent %d runes, want %d", len(runes), messageLimit)
	}
	if runes[len(runes)-1] != '\u2026' {
		t.Errorf("last rune = %q, want the ellipsis", runes[len(runes)-1])
	}
	if strings.ContainsRune(gotText, '\uFFFD') {
		t.Error("truncation split a rune")
	}
}

func TestSendMessageReportsApiError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized"}`))
	}))
	defer server.Close()

	err := New(testToken, server.URL).SendMessage(context.Background(), 1, "hi")
	if err == nil {
		t.Fatal("SendMessage accepted a 401")
	}
	if !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("error = %v, want the api description", err)
	}
}

// The token sits in the request path, so transport errors quote it. Nothing
// that reaches a log may contain it.
func TestErrorsNeverLeakTheToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close() // nothing is listening now, so the request fails at dial

	err := New(testToken, server.URL).SendMessage(context.Background(), 1, "hi")
	if err == nil {
		t.Fatal("SendMessage succeeded against a closed server")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("token leaked into %q", err)
	}
	if !strings.Contains(err.Error(), "REDACTED") {
		t.Errorf("error = %v, want the token replaced by REDACTED", err)
	}
}

func TestGetUpdates(t *testing.T) {
	var gotForm map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Write([]byte(`{"ok":true,"result":[
			{"update_id":11,"message":{"chat":{"id":42},"from":{"id":42,"username":"ng"},"text":"/allow 1.2.3.4"}},
			{"update_id":12,"message":{"chat":{"id":42},"from":{"id":42},"text":"/rules"}}
		]}`))
	}))
	defer server.Close()

	updates, err := New(testToken, server.URL).GetUpdates(context.Background(), 11, 25*time.Second)
	if err != nil {
		t.Fatalf("GetUpdates: %v", err)
	}
	if len(updates) != 2 {
		t.Fatalf("got %d updates, want 2", len(updates))
	}
	if updates[0].UpdateID != 11 || updates[0].Message.Text != "/allow 1.2.3.4" {
		t.Errorf("first update = %+v", updates[0])
	}
	if updates[0].Message.From.Username != "ng" {
		t.Errorf("username = %q, want ng", updates[0].Message.From.Username)
	}
	if got := gotForm["offset"]; len(got) != 1 || got[0] != "11" {
		t.Errorf("offset = %v, want 11", got)
	}
	if got := gotForm["timeout"]; len(got) != 1 || got[0] != "25" {
		t.Errorf("timeout = %v, want 25", got)
	}
}

// An update without a message must not panic the poller.
func TestGetUpdatesToleratesMessagelessUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"result":[{"update_id":5}]}`))
	}))
	defer server.Close()

	updates, err := New(testToken, server.URL).GetUpdates(context.Background(), 0, time.Second)
	if err != nil {
		t.Fatalf("GetUpdates: %v", err)
	}
	if len(updates) != 1 || updates[0].Message != nil {
		t.Fatalf("got %+v, want one update with no message", updates)
	}
}
