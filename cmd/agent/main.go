package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/agent"
	"github.com/NullGeorge/congenial-octo-doodle/internal/control"
	"github.com/NullGeorge/congenial-octo-doodle/internal/geoip"
	"github.com/NullGeorge/congenial-octo-doodle/internal/knockd"
	"github.com/NullGeorge/congenial-octo-doodle/internal/notify"
	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
	"github.com/NullGeorge/congenial-octo-doodle/internal/telegram"
	"github.com/NullGeorge/congenial-octo-doodle/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		if err := run(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "status":
		fmt.Println("knockd-agent: status command will be connected to systemd in the next step")
	case "rules":
		if err := listRules(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "version":
		fmt.Println("knockd-agent " + version.String())
	case "attempts":
		fmt.Println("knockd-agent: attempts command will be connected to the state store in the next step")
	default:
		usage()
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dbPath := fs.String("db", "/var/lib/knockd-agent/state.db", "SQLite database path")
	service := fs.String("service", "knockd", "systemd service name")
	geoPath := fs.String("geoip", "", "optional IPv4 country range CSV; disabled when empty")
	tokenPath := fs.String("telegram-token-file", "", "file holding the bot token; notifications are off when empty")
	chatID := fs.Int64("telegram-chat-id", 0, "chat that receives notifications")
	apiURL := fs.String("telegram-api", telegram.DefaultBaseURL, "Bot API base url; override only for testing")
	notifyEvery := fs.Duration("notify-interval", 10*time.Second, "how often the outbox is flushed")
	heartbeatURL := fs.String("heartbeat-url", "", "external watchdog url pinged on a schedule")
	heartbeatEvery := fs.Duration("heartbeat-interval", 5*time.Minute, "how often the watchdog is pinged")
	helperPath := fs.String("helper", "", "privileged helper binary; remote commands are off when empty")
	defaultTTL := fs.Duration("default-ttl", 15*time.Minute, "lifetime used by /allow when none is given")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var geo *geoip.DB
	if *geoPath != "" {
		loaded, err := geoip.Load(*geoPath)
		if err != nil {
			return err
		}
		geo = loaded
	}

	store, err := storage.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	engine := state.NewEngine(store)
	reader := knockd.NewLogReader(*service)
	runner := agent.New(reader, engine, geo, log.Default())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	token, chat, err := credentials(*tokenPath, *chatID)
	if err != nil {
		return err
	}
	notifying := token != ""
	commanding := notifying && *helperPath != ""
	if notifying {
		api := telegram.New(token, *apiURL)
		go notify.New(store, api, chat, log.Default()).Run(ctx, *notifyEvery)
		if commanding {
			helper := control.Helper{Path: *helperPath}
			go control.New(api, helper, engine, store, chat, *defaultTTL, log.Default()).Run(ctx)
		}
	}
	go notify.Heartbeat(ctx, *heartbeatURL, *heartbeatEvery, log.Default())

	log.Printf("starting knockd-agent %s", version.String())
	log.Printf("service=%s db=%s geoip=%d ranges notify=%t commands=%t heartbeat=%t",
		*service, *dbPath, geo.Len(), notifying, commanding, *heartbeatURL != "")
	return runner.Run(ctx)
}

// credentials resolves the bot token and chat from a file or, failing that,
// from BOT_TOKEN and CHAT_ID in the environment. Neither route puts the token
// in the process arguments, which every user on the host can read from ps;
// the environment route lets systemd read a root-only EnvironmentFile and
// hand the value to an unprivileged service.
func credentials(tokenPath string, chatID int64) (string, int64, error) {
	token := strings.TrimSpace(os.Getenv("BOT_TOKEN"))
	if tokenPath != "" {
		raw, err := os.ReadFile(tokenPath)
		if err != nil {
			return "", 0, fmt.Errorf("read telegram token: %w", err)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return "", 0, fmt.Errorf("telegram token file %s is empty", tokenPath)
		}
	}
	if token == "" {
		return "", 0, nil
	}

	if chatID == 0 {
		raw := strings.TrimSpace(os.Getenv("CHAT_ID"))
		if raw == "" {
			return "", 0, fmt.Errorf("a bot token is set but no chat: pass -telegram-chat-id or CHAT_ID")
		}
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return "", 0, fmt.Errorf("CHAT_ID %q is not a chat id: %w", raw, err)
		}
		chatID = parsed
	}
	return token, chatID, nil
}

// listRules prints the access the daemon recorded, with the lifetime each
// grant carried. Nothing here reads the live firewall, so it needs no
// privileges beyond the state database.
func listRules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	dbPath := fs.String("db", "/var/lib/knockd-agent/state.db", "SQLite database path")
	all := fs.Bool("all", false, "include rules whose lifetime already lapsed")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := storage.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	rules, err := store.ListRules()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "SOURCE IP\tRULE\tSTATE\tUPDATED\tEXPIRES")
	shown := 0
	for _, rule := range rules {
		expired := rule.Expired(now)
		if expired && !*all {
			continue
		}
		status := rule.State
		if expired && status == "open" {
			status = "expired"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", rule.SourceIP, rule.Rule, status,
			rule.UpdatedAt.UTC().Format(time.RFC3339), describeExpiry(rule.ExpiresAt, now))
		shown++
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if shown == 0 {
		fmt.Println("no active access rules")
	}
	return nil
}

func describeExpiry(expiresAt *time.Time, now time.Time) string {
	if expiresAt == nil {
		return "unknown"
	}
	if remaining := expiresAt.Sub(now); remaining > 0 {
		return "in " + remaining.Round(time.Second).String()
	}
	return now.Sub(*expiresAt).Round(time.Second).String() + " ago"
}

func usage() {
	fmt.Println("usage: knockd-agent <run|status|rules|attempts|version>")
	fmt.Println("       knockd-agent run   [-db path] [-service name] [-geoip path]")
	fmt.Println("       knockd-agent rules [-db path] [-all]")
}
