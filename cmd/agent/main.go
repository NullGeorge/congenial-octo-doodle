package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/agent"
	"github.com/NullGeorge/congenial-octo-doodle/internal/geoip"
	"github.com/NullGeorge/congenial-octo-doodle/internal/knockd"
	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
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

	log.Printf("starting knockd-agent service=%s db=%s geoip=%d ranges", *service, *dbPath, geo.Len())
	return runner.Run(ctx)
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
	fmt.Println("usage: knockd-agent <run|status|rules|attempts>")
	fmt.Println("       knockd-agent run   [-db path] [-service name] [-geoip path]")
	fmt.Println("       knockd-agent rules [-db path] [-all]")
}
