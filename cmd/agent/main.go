package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NullGeorge/congenial-octo-doodle/internal/agent"
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
		fmt.Println("knockd-agent: rules command will be connected to the state store in the next step")
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := storage.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	engine := state.NewEngine(store)
	reader := knockd.NewLogReader(*service)
	runner := agent.New(reader, engine, log.Default())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("starting knockd-agent service=%s db=%s", *service, *dbPath)
	return runner.Run(ctx)
}

func usage() {
	fmt.Println("usage: knockd-agent <run|status|rules|attempts>")
	fmt.Println("       knockd-agent run [-db path] [-service name]")
}
