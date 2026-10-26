# DDDNS: decentralized dynamic DNS

A network of peers that keeps a shared, signed DNS map up to date: which name
points at which (dynamic) IP. No central server. Members relay the data even
when no admin is online, and every change is signed by whoever was allowed to
make it.

- **Peer-to-peer:** [Hyperswarm](https://github.com/holepunchto/hyperswarm)
  handles discovery, NAT hole punching and encryption, so nodes find each other
  by a topic, not an address.
- **Automatic hostnames:** every node gets `n-<key>.<network>`, kept pointed at
  its public IP by the node itself. Admins can give nodes friendly names.
- **A DNS server** for your LAN (port 53, or 5300). It answers for the network's
  names and forwards everything else.
- **A dyndns2 update endpoint** for cameras and routers (Hikvision-compatible).
- **Roles and access:** admins, allowlist and blocklist modes, an optional
  network password, delegation of single hostnames.
- **Modules:** `dns`, `ddns` and `chat`. New ones plug into the core (see
  `core/module.py`).

## Setup

Needs **Python 3.10+** and **Node.js 18+**. Then, once per device, from the
project folder:

```
powershell -ExecutionPolicy Bypass -File setup.ps1      (Windows)
sh setup.sh                                             (Linux, macOS, Raspberry Pi)
```

This creates `venv/`, installs `requirements.txt` into it, and runs
`npm install` in `core/sidecar/`. Run it on every device rather than copying
`venv/` or `node_modules/`: some packages are compiled for one system.

## Running

```
venv\Scripts\python.exe main.py          (Windows)
venv/bin/python main.py                  (elsewhere)
```

Then `/create <name>` to start a network, or `/join <topic>` to join one.
`/help` lists every command. Useful options:

| option | what it does |
|---|---|
| `--network home` | open a saved network straight away (its name, number or topic) |
| `--headless` | no prompt: run as a service (below) |
| `--data DIR` | keep identity, networks and log somewhere other than `data/` |
| `--host 127.0.0.1` | serve DNS and DDNS to this machine only, not the LAN |
| `--upstream 9.9.9.9` | where names that aren't the network's are forwarded |
| `--no-dns`, `--no-ddns` | don't start that server |
| `--classic` | the plain console instead of the full terminal |

## Running as a service

A dynamic DNS is only as good as the nodes that are up. Run a few always-on
nodes, such as a Raspberry Pi, a home server or a VPS, headless:

```
python main.py --headless --network home
```

Join the network interactively once first; headless mode opens saved networks
only. What would have been shown goes to `data/dddns.log` and to stdout.

- **Linux:** [deploy/dddns.service](deploy/dddns.service) (systemd)
- **Windows:** [deploy/install-windows-task.ps1](deploy/install-windows-task.ps1)
  (Task Scheduler, at start-up)

## Your identity, and backing it up

`data/identity.json` is this device's identity: its private key, the same on
every network. **Never copy it to a second device that runs at the same time,
and never commit it** (`.gitignore` keeps `data/` out).

If an admin's device dies, its key is gone. To protect against that:

- `/identity -export <FILE>` writes an encrypted backup (you choose a
  passphrase). Keep it off the device, for example on a USB stick.
  `/identity -import <FILE>` restores it on a new device.
- Give the network a second admin (`/admin -append`).
- **Succession:** if no admin has been around for 30 days, the
  longest-standing member that is still around becomes admin by itself. Every
  node checks that claim against its own records first. Change the period
  with `/network -succession <DAYS>` or turn it off with
  `/network -succession off`. In blocklist mode, how long someone has been a
  member comes from the unsigned node ledger, so a member who has the password
  could fake it. In allowlist mode it comes from the signed allowlist.

## Housekeeping

- A node re-signs its own hostnames every week. A node's hostname that hasn't
  been re-signed for **90 days** expires on every node, because that node is gone.
  Names set by hand with `/dns -append` never expire. An admin can remove any
  name at once with `/dns -remove`.
- Nodes not seen for **180 days** drop out of the node ledger.
- **Peer limits:** a peer that sends more than 100 messages a second, a message
  over 8 MB, or a run of data with bad signatures is disconnected and refused
  for 10 minutes.

## Which address a name resolves to

A node's hostname isn't answered the same way everywhere. Each node publishes,
signed, its public IP, its LAN IP, and whether inbound connections are blocked
(behind NAT or a firewall). A node's DNS server then answers:

- **its own hostnames** with its current LAN IP (many routers can't loop back to
  their own public IP);
- **a node on the same LAN** with that node's LAN IP. "Same LAN" means this
  node's own Hyperswarm connection to it comes from exactly the LAN IP it
  published, which nobody can fake by writing data;
- **anything else** with the public IP.

Behind carrier-grade NAT the public IP isn't reachable from outside, and
`/dns -list` says so ("behind NAT/firewall"). Reaching such a host from another
LAN needs a tunnel through Hyperswarm, which is the next step.

## Using the DNS server from outside your LAN

The DNS server is meant for the LAN: point your router's DHCP DNS setting, or a
device, at the node. To query it over the internet you'd have to forward
UDP/TCP port 53 to it. Many ISPs and home routers block incoming port 53, so
check that from outside your network before relying on it. Usually it's simpler
to run a node on each LAN that needs the names.

## Tests

```
venv\Scripts\python.exe -m tests.run              all suites (a few minutes; uses the real DHT)
venv\Scripts\python.exe -m tests.run dns limits   only some
```

## Layout

```
main.py            entry point and options
core/              the network with nothing in it: identity, roles, signed sync, CLI
  sidecar/         Hyperswarm in Node.js; Python talks to it over stdin/stdout
modules/           dns/, ddns/, chat/ (enable or disable with /module)
deploy/            service files
tests/             python -m tests.run
data/              this device's identity, config, log and networks (not in git)
```

## Putting it in git

Install [Git](https://git-scm.com/download/win), then in the project folder:

```
git init
git add .
git commit -m "DDDNS"
```

`.gitignore` already leaves out `data/`, `venv/`, `node_modules/` and personal
PyCharm files. Check `git status` before your first commit: `data/` must not
appear.
