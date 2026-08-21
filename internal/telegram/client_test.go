package telegram

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// testdata/getupdates.json is a verbatim getUpdates response from the live bot,
// with only the account id replaced. It carries fields this client does not
// model (entities, language_code, is_premium, sticker), which is the point:
// the Bot API adds fields over time and a strict decoder would break on them.
func TestGetUpdatesDecodesARealApiResponse(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "getupdates.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer server.Close()

	updates, err := New(testToken, server.URL).GetUpdates(context.Background(), 0, time.Second)
	if err != nil {
		t.Fatalf("GetUpdates: %v", err)
	}
	if len(updates) != 6 {
		t.Fatalf("decoded %d updates, want 6", len(updates))
	}

	want := []struct {
		id   int64
		text string
	}{
		{id: 128673120, text: "/rules"},
		{id: 128673121, text: "/allow 192.0.2.1 5m"},
		{id: 128673122, text: "/knockd status"},
		// Typed on a Russian keyboard layout by mistake; it must reach the
		// controller as ordinary text rather than blow up on the way.
		{id: 128673123, text: "пгпшоз"},
		// Stickers are messages with no text field at all. A nil dereference
		// here would take the command poller down for the price of one emoji.
		{id: 128673124, text: ""},
		{id: 128673125, text: ""},
	}
	for i, expected := range want {
		got := updates[i]
		if got.UpdateID != expected.id {
			t.Errorf("update %d id = %d, want %d", i, got.UpdateID, expected.id)
		}
		if got.Message == nil {
			t.Fatalf("update %d has no message", i)
		}
		if got.Message.Text != expected.text {
			t.Errorf("update %d text = %q, want %q", i, got.Message.Text, expected.text)
		}
		if got.Message.Chat.ID != 111111111 {
			t.Errorf("update %d chat = %d, want the fixture chat", i, got.Message.Chat.ID)
		}
		if got.Message.From == nil || got.Message.From.ID != 111111111 {
			t.Errorf("update %d sender was not decoded: %+v", i, got.Message.From)
		}
	}
}

func TestNewDefaultsAndTrimsTheBaseURL(t *testing.T) {
	if got := New("t", "").baseURL; got != DefaultBaseURL {
		t.Errorf("empty base url = %q, want %q", got, DefaultBaseURL)
	}
	// A trailing slash from a config file must not produce a double slash in
	// the request path, which the Bot API answers with 404.
	if got := New("t", "http://stub:8080/").baseURL; got != "http://stub:8080" {
		t.Errorf("base url = %q, want the trailing slash removed", got)
	}
}

// The Bot API answers errors as JSON, but a proxy or a captive portal answers
// with HTML. That must be reported as unreadable rather than parsed as success.
func TestCallRejectsANonJsonResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	defer server.Close()

	err := New(testToken, server.URL).SendMessage(context.Background(), 1, "hi")
	if err == nil {
		t.Fatal("SendMessage accepted an HTML body")
	}
	for _, want := range []string{"sendMessage", "502", "unreadable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

// ok:true with a result that is not a list of updates must fail loudly; the
// poller would otherwise treat a broken response as "no commands".
func TestGetUpdatesRejectsAnUnexpectedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"result":{"not":"a list"}}`))
	}))
	defer server.Close()

	if _, err := New(testToken, server.URL).GetUpdates(context.Background(), 0, time.Second); err == nil {
		t.Fatal("GetUpdates accepted a result that is not a list")
	}
}

func TestGetUpdatesReportsAnApiError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}`))
	}))
	defer server.Close()

	_, err := New(testToken, server.URL).GetUpdates(context.Background(), 0, time.Second)
	if err == nil || !strings.Contains(err.Error(), "Conflict") {
		t.Fatalf("error = %v, want the api description", err)
	}
}

// A cancelled context must surface as an error rather than an empty result.
func TestCallHonoursTheContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New(testToken, server.URL).SendMessage(ctx, 1, "hi"); err == nil {
		t.Fatal("SendMessage succeeded with a cancelled context")
	}
}

// redact only rewrites when there is something to hide; a tokenless client
// must not have its errors mangled.
func TestRedactLeavesTokenlessErrorsAlone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()

	err := New("", server.URL).SendMessage(context.Background(), 1, "hi")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "REDACTED") {
		t.Errorf("error = %v, want it untouched when there is no token", err)
	}
}
