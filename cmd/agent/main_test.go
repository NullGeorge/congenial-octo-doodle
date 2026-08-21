package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/knockd"
	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
	"github.com/NullGeorge/congenial-octo-doodle/internal/version"
)

// knockdLines is one full knock captured from a live Debian 12 host running
// knockd 0.8, preceded by the timed-out sequence of an unrelated address.
// Seeding through these instead of hand-built rows keeps the reports honest:
// if the parser or the engine changes shape, these tests notice.
var knockdLines = []string{
	"starting up, listening on enp2s0",
	"192.0.2.134: openSSH: sequence timeout (stage 1)",
	"203.0.113.5: openSSH: Stage 1",
	"203.0.113.5: openSSH: Stage 2",
	"203.0.113.5: openSSH: Stage 3",
	"203.0.113.5: openSSH: OPEN SESAME",
	"openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.5 timeout 15m }",
	"shutting down",
}

// columnPadding matches the runs of spaces tabwriter inserts between columns.
var columnPadding = regexp.MustCompile(` {2,}`)

// normalizedLines reduces tabwriter's column padding to a single space. The
// cell values and their order are the contract; the exact padding width is
// not, and it shifts whenever an unrelated row gets longer.
func normalizedLines(out string) []string {
	trimmed := strings.TrimRight(out, "\n")
	if trimmed == "" {
		return nil
	}
	lines := strings.Split(trimmed, "\n")
	for i, line := range lines {
		lines[i] = columnPadding.ReplaceAllString(strings.TrimRight(line, " "), " ")
	}
	return lines
}

// capture runs fn with os.Stdout pointed at a pipe and returns everything the
// command printed along with the error it reported. The commands write to
// os.Stdout directly, so swapping the variable is the whole trick.
func capture(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = writer

	collected := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, reader)
		collected <- buf.String()
	}()

	runErr := fn()

	os.Stdout = saved
	if err := writer.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out := <-collected
	if err := reader.Close(); err != nil {
		t.Fatalf("close pipe reader: %v", err)
	}
	return out, runErr
}

// silenceStderr keeps flag's usage dump out of the test log. flag resolves
// os.Stderr on every write, so swapping the variable is enough.
func silenceStderr(t *testing.T) {
	t.Helper()

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	saved := os.Stderr
	os.Stderr = devNull
	t.Cleanup(func() {
		os.Stderr = saved
		_ = devNull.Close()
	})
}

// fakeSystemctl puts a stub systemctl first on PATH. unitState shells out, so
// this is the only way to pin its answer with no systemd in reach.
func fakeSystemctl(t *testing.T, script string) {
	t.Helper()

	dir := t.TempDir()
	stub := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// seedStore builds a state database the way the daemon does: real log lines
// through the real parser and the real engine. The returned base is the
// timestamp of the first line, so tests can predict what the reports print.
func seedStore(t *testing.T) (dbPath string, base time.Time) {
	t.Helper()

	dbPath = filepath.Join(t.TempDir(), "state.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// Anchored to now, never to a fixed date: the grant carries a fifteen
	// minute lifetime that the reports compare against the wall clock, so a
	// hardcoded base would make these tests start failing on their own.
	// Truncated to the second so the RFC3339 output is exactly predictable.
	base = time.Now().UTC().Add(-time.Minute).Truncate(time.Second)

	engine := state.NewEngine(store)
	for i, line := range knockdLines {
		event, ok := knockd.ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine(%q) ignored a real knockd line", line)
		}
		event.ID = strconv.Itoa(i)
		event.Timestamp = base.Add(time.Duration(i) * time.Second)
		if err := engine.Apply(event); err != nil {
			t.Fatalf("apply %q: %v", line, err)
		}
	}
	return dbPath, base
}

// emptyStore is a migrated database that has never seen an event.
func emptyStore(t *testing.T) string {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "state.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	return dbPath
}

// saveRule stores a rule straight through the storage layer, which is how a
// grant whose lifetime has already lapsed gets into the database without
// waiting a quarter of an hour for it.
func saveRule(t *testing.T, dbPath string, rule storage.AccessRule) {
	t.Helper()

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if err := store.SaveRule(rule); err != nil {
		t.Fatalf("save rule: %v", err)
	}
}

func TestCredentials(t *testing.T) {
	dir := t.TempDir()

	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	emptyFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyFile, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write empty token file: %v", err)
	}
	missingFile := filepath.Join(dir, "absent")

	tests := []struct {
		name      string
		tokenPath string
		chatID    int64
		botToken  string
		chatEnv   string
		wantToken string
		wantChat  int64
		wantErr   bool
	}{
		{
			// A file lets systemd keep the secret out of the environment
			// entirely, so when one is named it has to win outright.
			name:      "token file beats the environment",
			tokenPath: tokenFile,
			chatID:    42,
			botToken:  "env-token",
			wantToken: "file-token",
			wantChat:  42,
		},
		{
			name:      "environment supplies token and chat",
			tokenPath: "",
			botToken:  "env-token",
			chatEnv:   "777",
			wantToken: "env-token",
			wantChat:  777,
		},
		{
			// EnvironmentFile values arrive with whatever whitespace the
			// operator's editor left behind.
			name:      "environment values are trimmed",
			botToken:  "  env-token  ",
			chatEnv:   " 777 ",
			wantToken: "env-token",
			wantChat:  777,
		},
		{
			// The flag is explicit; CHAT_ID is only the fallback.
			name:      "explicit chat id ignores CHAT_ID",
			botToken:  "env-token",
			chatID:    42,
			chatEnv:   "777",
			wantToken: "env-token",
			wantChat:  42,
		},
		{
			// A named file that is not there is a deployment mistake, not a
			// reason to run silently without alerts.
			name:      "missing token file",
			tokenPath: missingFile,
			chatID:    42,
			wantErr:   true,
		},
		{
			// A truncated secret file must not read as "notifications off".
			name:      "empty token file",
			tokenPath: emptyFile,
			chatID:    42,
			wantErr:   true,
		},
		{
			// A token with nowhere to send is misconfigured: the messages
			// would be built and then dropped.
			name:     "token without any chat",
			botToken: "env-token",
			wantErr:  true,
		},
		{
			name:     "non numeric CHAT_ID",
			botToken: "env-token",
			chatEnv:  "not-a-chat",
			wantErr:  true,
		},
		{
			// No token anywhere is the supported way to run with
			// notifications switched off, so it must not be an error.
			name:      "no token anywhere",
			wantToken: "",
			wantChat:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set both unconditionally so the host's own environment cannot
			// leak into a case; t.Setenv restores them afterwards.
			t.Setenv("BOT_TOKEN", tt.botToken)
			t.Setenv("CHAT_ID", tt.chatEnv)

			token, chat, err := credentials(tt.tokenPath, tt.chatID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("credentials(%q, %d) = %q, %d, want an error",
						tt.tokenPath, tt.chatID, token, chat)
				}
				// A failed lookup must not hand back a half-usable pair.
				if token != "" || chat != 0 {
					t.Errorf("credentials returned %q, %d alongside error %v", token, chat, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("credentials(%q, %d): %v", tt.tokenPath, tt.chatID, err)
			}
			if token != tt.wantToken {
				t.Errorf("token = %q, want %q", token, tt.wantToken)
			}
			if chat != tt.wantChat {
				t.Errorf("chat = %d, want %d", chat, tt.wantChat)
			}
		})
	}
}

func TestDescribeExpiry(t *testing.T) {
	// Anchored to the now that is passed in, so this cannot start failing
	// once real time moves past some date written into the source.
	now := time.Now().UTC()
	future := now.Add(15 * time.Minute)
	past := now.Add(-90 * time.Second)
	exactlyNow := now

	tests := []struct {
		name string
		in   *time.Time
		want string
	}{
		{
			// knockd commands without a timeout grant access until someone
			// removes it, and the agent does not read the live ruleset.
			name: "no lifetime known",
			in:   nil,
			want: "unknown",
		},
		{
			name: "still open",
			in:   &future,
			want: "in 15m0s",
		},
		{
			name: "already lapsed",
			in:   &past,
			want: "1m30s ago",
		},
		{
			// A lifetime that runs out exactly now is spent, not "in 0s":
			// the boundary decides whether the operator sees live access.
			name: "lapsing exactly now",
			in:   &exactlyNow,
			want: "0s ago",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeExpiry(tt.in, now); got != tt.want {
				t.Errorf("describeExpiry = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnitState(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		service string
		want    string
	}{
		{
			name:    "running unit",
			script:  "echo active",
			service: "knockd",
			want:    "active",
		},
		{
			// The queried unit comes from -service, so the subcommand and the
			// name both have to reach systemctl in that order.
			name:    "arguments reach systemctl",
			script:  `echo "$1 $2"`,
			service: "knockd@wan",
			want:    "is-active knockd@wan",
		},
		{
			// A stopped unit makes systemctl exit non-zero while still
			// printing its verdict, which is an answer and not a failure.
			name:    "stopped unit still answers",
			script:  "echo inactive; exit 3",
			service: "knockd",
			want:    "inactive",
		},
		{
			// No output at all means systemd could not be reached; the
			// status report must say so rather than invent a state.
			name:    "silent failure",
			script:  "exit 1",
			service: "knockd",
			want:    "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeSystemctl(t, tt.script)
			if got := unitState(tt.service); got != tt.want {
				t.Errorf("unitState(%q) = %q, want %q", tt.service, got, tt.want)
			}
		})
	}
}

func TestShowStatusReportsSeededDatabase(t *testing.T) {
	dbPath, base := seedStore(t)
	fakeSystemctl(t, "echo active")

	out, err := capture(t, func() error {
		return showStatus([]string{"-db", dbPath, "-service", "knockd"})
	})
	if err != nil {
		t.Fatalf("showStatus: %v", err)
	}

	// Eight lines were fed in and none has been pushed to Telegram, the two
	// knocks plus the timed-out sequence are the attempts, and the grant is
	// the single rule still inside its fifteen minute lifetime.
	want := []string{
		"version " + version.String(),
		"database " + dbPath,
		"knockd unit active",
		"events 8 recorded, 8 not yet delivered",
		"last event knockd.stopped at " + base.Add(7*time.Second).Format(time.RFC3339),
		"attempts 3 recorded",
		"active access 1 rule(s)",
	}
	got := normalizedLines(out)
	if len(got) != len(want) {
		t.Fatalf("status printed %d lines, want %d:\n%s", len(got), len(want), out)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("status line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestShowStatusOnEmptyDatabase(t *testing.T) {
	fakeSystemctl(t, "echo active")

	out, err := capture(t, func() error {
		return showStatus([]string{"-db", emptyStore(t)})
	})
	if err != nil {
		t.Fatalf("showStatus: %v", err)
	}

	got := normalizedLines(out)
	// With no events there is nothing to report as the last one, so that row
	// is left out entirely rather than printed with a zero timestamp.
	for _, line := range got {
		if strings.HasPrefix(line, "last event") {
			t.Errorf("empty database reported a last event: %q", line)
		}
	}
	for _, want := range []string{
		"events 0 recorded, 0 not yet delivered",
		"attempts 0 recorded",
		"active access 0 rule(s)",
	} {
		if !containsLine(got, want) {
			t.Errorf("status is missing %q:\n%s", want, out)
		}
	}
}

func TestListRulesShowsLiveGrant(t *testing.T) {
	dbPath, base := seedStore(t)

	out, err := capture(t, func() error {
		return listRules([]string{"-db", dbPath})
	})
	if err != nil {
		t.Fatalf("listRules: %v", err)
	}

	got := normalizedLines(out)
	if len(got) != 2 {
		t.Fatalf("rules printed %d lines, want a header and one rule:\n%s", len(got), out)
	}
	if want := "SOURCE IP RULE STATE UPDATED EXPIRES"; got[0] != want {
		t.Errorf("header = %q, want %q", got[0], want)
	}

	// The grant is the seventh line, so it is stamped base+6s, and its
	// remaining lifetime is whatever is left of fifteen minutes right now.
	fields := strings.Fields(got[1])
	wantFields := []string{"203.0.113.5", "openSSH", "open", base.Add(6 * time.Second).Format(time.RFC3339), "in"}
	if len(fields) != len(wantFields)+1 {
		t.Fatalf("rule row = %q, want ip, rule, state, updated and a remaining lifetime", got[1])
	}
	for i, want := range wantFields {
		if fields[i] != want {
			t.Errorf("rule field %d = %q, want %q", i, fields[i], want)
		}
	}
	if _, err := time.ParseDuration(fields[5]); err != nil {
		t.Errorf("remaining lifetime %q is not a duration: %v", fields[5], err)
	}
}

func TestListRulesHidesExpiredUnlessAll(t *testing.T) {
	dbPath, base := seedStore(t)

	// An hour-old grant with a fifteen minute lifetime: recorded as open,
	// but the address can no longer reach the port.
	expiresAt := base.Add(-time.Hour)
	saveRule(t, dbPath, storage.AccessRule{
		SourceIP:  "198.51.100.167",
		Rule:      "openSSH",
		Port:      22,
		Protocol:  "tcp",
		State:     "open",
		Source:    "knockd",
		UpdatedAt: base.Add(-90 * time.Minute),
		ExpiresAt: &expiresAt,
	})

	defaultOut, err := capture(t, func() error {
		return listRules([]string{"-db", dbPath})
	})
	if err != nil {
		t.Fatalf("listRules: %v", err)
	}
	if strings.Contains(defaultOut, "198.51.100.167") {
		t.Errorf("a lapsed grant was listed without -all:\n%s", defaultOut)
	}
	if !strings.Contains(defaultOut, "203.0.113.5") {
		t.Errorf("the live grant is missing:\n%s", defaultOut)
	}

	allOut, err := capture(t, func() error {
		return listRules([]string{"-db", dbPath, "-all"})
	})
	if err != nil {
		t.Fatalf("listRules -all: %v", err)
	}

	got := normalizedLines(allOut)
	if len(got) != 3 {
		t.Fatalf("rules -all printed %d lines, want a header and two rules:\n%s", len(got), allOut)
	}

	// Rules come out oldest first, so the lapsed one leads.
	fields := strings.Fields(got[1])
	wantFields := []string{"198.51.100.167", "openSSH", "expired", base.Add(-90 * time.Minute).Format(time.RFC3339)}
	if len(fields) != len(wantFields)+2 {
		t.Fatalf("lapsed row = %q, want ip, rule, state, updated and an elapsed lifetime", got[1])
	}
	for i, want := range wantFields {
		if fields[i] != want {
			t.Errorf("lapsed field %d = %q, want %q", i, fields[i], want)
		}
	}
	// A rule recorded as open but past its lifetime reads as expired, and its
	// expiry is stated as time gone by rather than time remaining.
	if fields[5] != "ago" {
		t.Errorf("lapsed expiry = %q %q, want a duration followed by ago", fields[4], fields[5])
	}
	if !strings.Contains(got[2], "203.0.113.5") {
		t.Errorf("the live grant is missing from -all output: %q", got[2])
	}
}

func TestListRulesOnEmptyDatabase(t *testing.T) {
	out, err := capture(t, func() error {
		return listRules([]string{"-db", emptyStore(t)})
	})
	if err != nil {
		t.Fatalf("listRules: %v", err)
	}

	got := normalizedLines(out)
	want := []string{"SOURCE IP RULE STATE UPDATED EXPIRES", "no active access rules"}
	if len(got) != len(want) {
		t.Fatalf("rules printed %d lines, want %d:\n%s", len(got), len(want), out)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestListAttemptsShowsNewestFirst(t *testing.T) {
	dbPath, base := seedStore(t)

	out, err := capture(t, func() error {
		return listAttempts([]string{"-db", dbPath})
	})
	if err != nil {
		t.Fatalf("listAttempts: %v", err)
	}

	// Stage 1 opens a sequence and is not an attempt on its own; stages 2 and
	// 3 are knocks and the timed-out sequence is a failure. Newest first, so
	// the other host's timeout sinks to the bottom.
	want := []string{
		"TIME SOURCE IP RULE STATUS",
		base.Add(4*time.Second).Format(time.RFC3339) + " 203.0.113.5 openSSH knock.received",
		base.Add(3*time.Second).Format(time.RFC3339) + " 203.0.113.5 openSSH knock.received",
		base.Add(1*time.Second).Format(time.RFC3339) + " 192.0.2.134 openSSH knock.sequence_failed",
	}
	got := normalizedLines(out)
	if len(got) != len(want) {
		t.Fatalf("attempts printed %d lines, want %d:\n%s", len(got), len(want), out)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("attempt line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestListAttemptsHonoursLimit(t *testing.T) {
	dbPath, base := seedStore(t)

	out, err := capture(t, func() error {
		return listAttempts([]string{"-db", dbPath, "-limit", "1"})
	})
	if err != nil {
		t.Fatalf("listAttempts: %v", err)
	}

	// -limit keeps the newest, which is the point of asking for a few.
	got := normalizedLines(out)
	want := []string{
		"TIME SOURCE IP RULE STATUS",
		base.Add(4*time.Second).Format(time.RFC3339) + " 203.0.113.5 openSSH knock.received",
	}
	if len(got) != len(want) {
		t.Fatalf("attempts printed %d lines, want %d:\n%s", len(got), len(want), out)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("attempt line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestListAttemptsOnEmptyDatabase(t *testing.T) {
	out, err := capture(t, func() error {
		return listAttempts([]string{"-db", emptyStore(t)})
	})
	if err != nil {
		t.Fatalf("listAttempts: %v", err)
	}

	// A bare header over nothing looks like a broken command; say it plainly.
	got := normalizedLines(out)
	if len(got) != 1 || got[0] != "no recorded attempts" {
		t.Errorf("attempts on an empty database printed %q, want the no recorded attempts line", out)
	}
}

// The commands are the operator's only view of the state database, so a
// database they cannot open has to be reported. Printing an empty report
// would read as "nothing has ever happened here".
func TestCommandsRejectUnopenableDatabase(t *testing.T) {
	// A path under a directory that does not exist: SQLite will not create
	// the parent, so opening it fails.
	missing := filepath.Join(t.TempDir(), "absent-dir", "state.db")

	for name, command := range map[string]func([]string) error{
		"status":   showStatus,
		"rules":    listRules,
		"attempts": listAttempts,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := capture(t, func() error {
				return command([]string{"-db", missing})
			})
			if err == nil {
				t.Fatalf("%s reported success on an unopenable database, printing %q", name, out)
			}
			if out != "" {
				t.Errorf("%s printed a report despite failing: %q", name, out)
			}
		})
	}
}

func TestCommandsRejectUnknownFlags(t *testing.T) {
	silenceStderr(t)

	for name, command := range map[string]func([]string) error{
		"run":      run,
		"status":   showStatus,
		"rules":    listRules,
		"attempts": listAttempts,
	} {
		t.Run(name, func(t *testing.T) {
			// A typo in a flag must stop the command rather than fall through
			// to the default database, which for run means following the log.
			if err := command([]string{"-not-a-flag"}); err == nil {
				t.Fatalf("%s accepted an undefined flag", name)
			}
		})
	}
}

// run is a daemon, but every one of its startup checks has to fail before it
// begins following the log, or a misconfigured unit sits there doing nothing.
func TestRunRejectsBadStartup(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			// Loading the geolocation database is attempted before anything
			// else, so a bad path fails fast and leaves no database behind.
			name: "missing geoip database",
			args: []string{"-db", filepath.Join(dir, "geo.db"), "-geoip", filepath.Join(dir, "absent.csv")},
			want: "open geoip database",
		},
		{
			name: "unopenable state database",
			args: []string{"-db", filepath.Join(dir, "absent-dir", "state.db")},
			want: "",
		},
		{
			// A named token file that is missing means notifications were
			// meant to be on; starting without them would hide every knock.
			name: "missing telegram token file",
			args: []string{"-db", filepath.Join(dir, "token.db"), "-telegram-token-file", filepath.Join(dir, "absent-token")},
			want: "read telegram token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A token in the environment must not paper over a named file.
			t.Setenv("BOT_TOKEN", "")
			t.Setenv("CHAT_ID", "")

			err := run(tt.args)
			if err == nil {
				t.Fatalf("run(%v) started the daemon instead of failing", tt.args)
			}
			if tt.want != "" && !strings.Contains(err.Error(), tt.want) {
				t.Errorf("run(%v) error = %v, want it to mention %q", tt.args, err, tt.want)
			}
		})
	}
}

// usage is what a mistyped command prints, so it has to name every subcommand
// main actually dispatches; a forgotten one is invisible to the operator.
func TestUsageNamesEverySubcommand(t *testing.T) {
	out, err := capture(t, func() error {
		usage()
		return nil
	})
	if err != nil {
		t.Fatalf("usage: %v", err)
	}

	for _, command := range []string{"run", "status", "rules", "attempts", "version"} {
		if !strings.Contains(out, command) {
			t.Errorf("usage does not mention the %s subcommand:\n%s", command, out)
		}
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}
