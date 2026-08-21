# knockd-agent

Watches a [knockd](https://linux.die.net/man/1/knockd) log, records who knocked
and who was granted access, reports it to Telegram, and optionally lets you
grant access from the chat.

The daemon holds **no capabilities at all**. Everything privileged lives in a
separate binary that runs for the duration of one command.

## What it does

- Parses the real knockd 0.8 log format: sequence stages, timeouts, matched
  sequences and the firewall commands knockd executes.
- Decides grant versus revoke from the executed command, never from the
  section name. Section names are operator-chosen, so `openSSH` appears in
  every line of that section, and classifying on it reports one knock as five
  grants.
- Derives when access lapses from the lifetime written into the command
  (`nft add element ... timeout 15m`), so no privileged read of the live
  ruleset is needed.
- Labels each address with a country from a local range table. No lookup ever
  leaves the host.
- Pushes noteworthy events to Telegram. The database doubles as the outbox, so
  an outage delays alerts rather than losing them.

## Privilege model

Measured on Debian 12, not assumed:

| Operation | What it actually requires |
|---|---|
| Read the knockd journal | membership in `systemd-journal`. Not root |
| Write the state database | its own `StateDirectory` |
| Read **or** write nftables | `CAP_NET_ADMIN` — there is no read-only mode |

Because reading the ruleset costs the same capability as rewriting it, the
daemon does not read it. It learns lifetimes from the log instead.

```
journalctl ──> knockd-agent (CapEff=0, always running) ──> state.db ──> Telegram
                     │
                     └── sudo ──> knock-helper (root, milliseconds) ──> nft / systemctl
```

`knock-helper` validates its own arguments and builds fixed templates against
one named set. The address is re-rendered from a parsed `netip` value, so a
caller argument can never become nft syntax. Grants are bounded to 1m..24h.

Enabling chat commands is a deliberate trade, because sudo is setuid and
cannot run under the hardened defaults:

```
CapabilityBoundingSet=  (empty)  -> sudo: unable to change to root gid
NoNewPrivileges=true             -> sudo: the "no new privileges" flag is set
```

The bounding set also caps root itself: without `CAP_NET_ADMIN` in it, the
helper reaches nft and is refused with "you must be root". See the comments in
`configs/knockd-agent.service` for the exact lines to change.

## Install

```sh
make build   # dist/knockd-agent, dist/knock-helper, dist/knock-watch
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin knockd-agent
install -m 0755 dist/knockd-agent /usr/local/bin/
install -m 0644 configs/knockd-agent.service /etc/systemd/system/
```

Credentials, `0600 root:root`. systemd reads this as root before dropping
privileges, so the file stays unreadable to the service user:

```sh
printf 'BOT_TOKEN=...\nCHAT_ID=...\n' > /etc/knockd-agent.env
chmod 600 /etc/knockd-agent.env
systemctl daemon-reload && systemctl enable --now knockd-agent
```

Country labels are optional. Fetch the table (PDDL, no attribution required),
then add `-geoip /var/lib/knockd-agent/country.csv` to `ExecStart`:

```sh
curl -sSL -o /var/lib/knockd-agent/country.csv \
  https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv4-num.csv
```

Chat commands, only if you accept the trade above:

```sh
install -m 0755 dist/knock-helper /usr/local/sbin/
install -m 0440 configs/sudoers.knockd-agent /etc/sudoers.d/knockd-agent
visudo -c
```

## Commands

Locally:

```
knockd-agent run      [-db path] [-service name] [-geoip path] [-helper path]
knockd-agent status   [-db path] [-service name]
knockd-agent rules    [-db path] [-all]
knockd-agent attempts [-db path] [-limit n]
knockd-agent version
```

From the chat, accepted from one `CHAT_ID` only. Any other chat is ignored
without a reply, so probing reveals nothing:

```
/allow <ipv4> [duration]   default lifetime when omitted
/revoke <ipv4>
/rules
/knockd <start|stop|restart|status>
```

## Watchdog

`knock-watch` is the other half of `-heartbeat-url`, and it must run on a
different machine: a dead host cannot report its own death.

The agent checks in on a schedule. If check-ins stop for longer than `-grace`,
the watchdog messages you **once**, and messages you again when they resume. A
continuing outage does not repeat, because an alert that repeats every tick is
an alert you learn to ignore.

Fetch and build it on that machine:

```sh
wget -qO- https://github.com/NullGeorge/congenial-octo-doodle/archive/refs/tags/v0.2.0.tar.gz | tar xz
cd congenial-octo-doodle-0.2.0
make build                              # needs Docker, produces dist/knock-watch
go build -o knock-watch ./cmd/knock-watch   # or this, with a Go toolchain
```

Run it with the same two variables the agent uses:

```sh
BOT_TOKEN=... CHAT_ID=... knock-watch \
  -listen :9000 -token <secret> -name atsos -grace 15m
```

Then point the agent at it:

```
-heartbeat-url https://watch.example.com/ping/<secret> -heartbeat-interval 5m
```

`-token` is required and the program refuses to start without one. Anyone able
to reach the ping URL can keep the alert suppressed forever, which is exactly
the failure being guarded against. Pick `-grace` at a few times the heartbeat
interval so one lost request is not an outage.

Last-seen is persisted, so restarting the watchdog neither forgets an
outstanding alert nor re-sends one.

## Keeping the ports reachable behind a UPnP router

knockd sniffs the wire, it never binds a socket. Nothing on the host ever
opens the sequence ports, so a home router has no reason to forward them and
no reason to keep a UPnP lease alive. Leases expire, reboots wipe the table,
and from then on every knock dies at the gateway. The symptom is nasty
because it looks exactly like a wrong sequence: the journal stays empty and
the agent has nothing to report.

`configs/knock-portmap` re-asserts the mappings. It reads the ports out of
knockd.conf rather than repeating them, so changing the sequence cannot leave
the old ports open and the new ones shut.

```sh
apt install miniupnpc
install -m 0755 configs/knock-portmap /usr/local/sbin/
install -m 0644 configs/knock-portmap.service configs/knock-portmap.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now knock-portmap.timer
```

The timer runs a minute after boot, because the gateway often comes up later
than the host, and every fifteen minutes after that. Re-adding an existing
mapping is a no-op, so it is safe to run by hand at any time:

```sh
knock-portmap && upnpc -l
```

This helps only where the router hands out a real public address. Behind
carrier-grade NAT the mapping will be created and still nothing will arrive,
because the address the router thinks it owns is not the one the internet
routes to. Two signs to check first: a private next hop in `traceroute`, and
`upnpc -s` reporting an external address that differs from what an outside
service like icanhazip.com sees.

## Build and test

There is no local Go toolchain requirement; everything runs in Docker.

```sh
make docker-test    # go test ./...
make build          # both binaries into dist/
make version        # what the next build will stamp
```

Versions come from `git describe`, stamped through `-ldflags` into both
binaries. `knockd-agent version` reports it, and so does the startup log. The
build date is the commit date, so rebuilding a commit is reproducible.

## Known limitations

- Changes made to the nftables set outside knockd, a `nft flush`, or a reboot
  are invisible to the agent. It knows only what the log said. Closing that
  gap costs `CAP_NET_ADMIN`, which is the thing being avoided.
- knockd 0.8 is IPv4 only, so the parser and the country table are too.
- Every `sudo` invocation logs three `pam_limits` lines to the journal because
  the service user may not raise its own limits. Cosmetic, and left alone
  rather than patching PAM.
