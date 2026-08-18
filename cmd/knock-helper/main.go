// Command knock-helper performs the few privileged actions the agent needs
// and nothing else. It runs as root for milliseconds at a time, invoked
// through sudo, and never sees untrusted input from the network: the daemon
// that parses the journal hands it an address and a duration, both of which
// are validated here before any command is built.
//
// The firewall target is fixed at compile time on purpose. An argument can
// never become part of the nft syntax, so there is no way to turn this into a
// general purpose "run nft for me" service.
package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	nftPath       = "/usr/sbin/nft"
	systemctlPath = "/usr/bin/systemctl"

	family  = "inet"
	table   = "portknock"
	setName = "ssh_allowed"
	service = "knockd"

	// A grant shorter than this is useless, and one longer than this is a
	// standing hole rather than temporary access.
	minTTL = time.Minute
	maxTTL = 24 * time.Hour
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	switch args[0] {
	case "allow":
		if len(args) != 3 {
			return fmt.Errorf("usage: knock-helper allow <ipv4> <duration>")
		}
		argv, err := allowArgs(args[1], args[2])
		if err != nil {
			return err
		}
		if err := execute(nftPath, argv); err != nil {
			return err
		}
		fmt.Printf("allowed %s for %s\n", args[1], args[2])

	case "revoke":
		if len(args) != 2 {
			return fmt.Errorf("usage: knock-helper revoke <ipv4>")
		}
		argv, err := revokeArgs(args[1])
		if err != nil {
			return err
		}
		if err := execute(nftPath, argv); err != nil {
			return err
		}
		fmt.Printf("revoked %s\n", args[1])

	case "service":
		if len(args) != 2 {
			return fmt.Errorf("usage: knock-helper service <start|stop|restart|status>")
		}
		argv, err := serviceArgs(args[1])
		if err != nil {
			return err
		}
		output, err := exec.Command(systemctlPath, argv...).CombinedOutput()
		trimmed := strings.TrimSpace(string(output))
		// systemctl is-active exits non-zero for an inactive unit, which is an
		// answer rather than a failure, so status reports the text either way.
		if args[1] == "status" {
			if trimmed == "" {
				trimmed = "unknown"
			}
			fmt.Println(trimmed)
			return nil
		}
		if err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", args[1], err, trimmed)
		}
		fmt.Printf("knockd %s ok\n", args[1])

	default:
		return usage()
	}
	return nil
}

func usage() error {
	return fmt.Errorf("usage: knock-helper <allow <ipv4> <duration>|revoke <ipv4>|service <start|stop|restart|status>>")
}

// allowArgs builds the element insert. The address is re-rendered from the
// parsed value, so whatever the caller typed never reaches the command line.
func allowArgs(address, duration string) ([]string, error) {
	ip, err := parseIPv4(address)
	if err != nil {
		return nil, err
	}
	ttl, err := parseTTL(duration)
	if err != nil {
		return nil, err
	}
	seconds := strconv.FormatInt(int64(ttl/time.Second), 10) + "s"
	return []string{"add", "element", family, table, setName,
		"{", ip, "timeout", seconds, "}"}, nil
}

func revokeArgs(address string) ([]string, error) {
	ip, err := parseIPv4(address)
	if err != nil {
		return nil, err
	}
	return []string{"delete", "element", family, table, setName, "{", ip, "}"}, nil
}

func serviceArgs(verb string) ([]string, error) {
	switch verb {
	case "start", "stop", "restart":
		return []string{verb, service}, nil
	case "status":
		return []string{"is-active", service}, nil
	default:
		return nil, fmt.Errorf("unknown verb %q: allowed are start, stop, restart, status", verb)
	}
}

func parseIPv4(address string) (string, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return "", fmt.Errorf("%q is not an ip address", address)
	}
	if !ip.Is4() {
		return "", fmt.Errorf("%s is not IPv4, and the set holds ipv4_addr", address)
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return "", fmt.Errorf("%s is not a routable public address", address)
	}
	return ip.String(), nil
}

func parseTTL(duration string) (time.Duration, error) {
	ttl, err := time.ParseDuration(duration)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration, try 15m or 2h", duration)
	}
	if ttl < minTTL || ttl > maxTTL {
		return 0, fmt.Errorf("duration %s is outside the allowed range %s..%s", ttl, minTTL, maxTTL)
	}
	return ttl, nil
}

func execute(binary string, argv []string) error {
	output, err := exec.Command(binary, argv...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", binary, strings.Join(argv, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
