// Package telegram is a minimal Bot API client: the two calls this agent
// needs, over outbound HTTPS only. The protected host never listens, so
// nothing here accepts a connection.
package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public Bot API endpoint. Tests point this elsewhere.
const DefaultBaseURL = "https://api.telegram.org"

// messageLimit is the Bot API ceiling for a single text message.
const messageLimit = 4096

type Client struct {
	token   string
	baseURL string
	http    *http.Client
}

// New builds a client. The timeout has to exceed the long poll window used by
// GetUpdates, so it is set per call instead of on the shared client.
func New(token, baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		token:   token,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		http:    &http.Client{},
	}
}

// Chat and sender identity are all this agent inspects; the rest of the Bot
// API payload is deliberately ignored.
type Update struct {
	UpdateID int64    `json:"update_id"`
	Message  *Message `json:"message"`
}

type Message struct {
	Chat Chat   `json:"chat"`
	From *User  `json:"from"`
	Text string `json:"text"`
}

type Chat struct {
	ID int64 `json:"id"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type envelope struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
	ErrorCode   int             `json:"error_code"`
}

// SendMessage delivers one notification. Over-long text is truncated rather
// than rejected, because a clipped alert beats a dropped one.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string) error {
	// The Bot API counts characters, not bytes, and a byte slice would both
	// overshoot the limit and risk cutting a rune in half.
	if runes := []rune(text); len(runes) > messageLimit {
		text = string(runes[:messageLimit-1]) + "\u2026"
	}
	form := url.Values{
		"chat_id":                  {strconv.FormatInt(chatID, 10)},
		"text":                     {text},
		"disable_web_page_preview": {"true"},
	}
	_, err := c.call(ctx, "sendMessage", form, 30*time.Second)
	return err
}

// GetUpdates long polls for commands. offset is the id after the last update
// already handled, which is how the Bot API acknowledges delivery.
func (c *Client) GetUpdates(ctx context.Context, offset int64, wait time.Duration) ([]Update, error) {
	form := url.Values{
		"offset":          {strconv.FormatInt(offset, 10)},
		"timeout":         {strconv.FormatInt(int64(wait/time.Second), 10)},
		"allowed_updates": {`["message"]`},
	}
	// The HTTP deadline must outlast the server side long poll window.
	body, err := c.call(ctx, "getUpdates", form, wait+30*time.Second)
	if err != nil {
		return nil, err
	}

	var updates []Update
	if err := json.Unmarshal(body, &updates); err != nil {
		return nil, fmt.Errorf("decode updates: %w", err)
	}
	return updates, nil
}

func (c *Client) call(ctx context.Context, method string, form url.Values, timeout time.Duration) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := c.baseURL + "/bot" + c.token + "/" + method
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, c.redact(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.http.Do(request)
	if err != nil {
		return nil, c.redact(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, c.redact(err)
	}

	var parsed envelope
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("%s: http %d: unreadable response", method, response.StatusCode)
	}
	if !parsed.OK {
		return nil, fmt.Errorf("%s: telegram error %d: %s", method, parsed.ErrorCode, parsed.Description)
	}
	return parsed.Result, nil
}

// redact keeps the bot token out of logs. Transport errors quote the request
// URL, and the token is part of that path.
func (c *Client) redact(err error) error {
	if c.token == "" {
		return err
	}
	message := strings.ReplaceAll(err.Error(), c.token, "REDACTED")
	return fmt.Errorf("%s", message)
}
