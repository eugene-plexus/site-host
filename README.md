# Eugene Plexus — `site-host`

[![CI](https://github.com/eugene-plexus/site-host/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/eugene-plexus/site-host/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB.svg)](https://www.python.org)

The piece of [Eugene Plexus](https://github.com/eugene-plexus) that runs a
machine's tools for Workbench: a **local MCP host** whose policy is final on
that machine.

- **Eugene's own file server**, one per folder registered on the machine:
  `list_directory`, `read_text` and, on a writable folder, `write_text`.
- **Local MCP servers** a machine administrator adds at the machine.

Its contract is [`openapi/site-host.yaml`](https://github.com/eugene-plexus/specs/blob/main/openapi/site-host.yaml)
in `specs`; the design is
[`docs/design/remote-nodes.md`](https://github.com/eugene-plexus/specs/blob/main/docs/design/remote-nodes.md)
§3.4 and §6.2.

## What it is, and what it is not

**It decides.** Every request reaches it as one MCP request of the 2026-07-28
revision, relayed by the machine's agent from the root's queue. The host checks
the server, the person and the tool against its own policy before anything runs,
and records the call in an audit log kept on the machine. Nothing upstream can
make it run what it refuses.

- **Default deny.** A server is off until its owner turns it on (a folder's
  server is on while the folder is registered), and a person may use only the
  tools the owner named for them.
- **Destructive tools need a standing pre-approval.** A tool the server does
  not mark read-only is treated as able to change something, as MCP itself
  defaults.
- **A `system` server** (one that could alter the operating system) cannot be
  turned on without an administrator's consent recorded at the machine.

**On a Job Site** (`site` mode) the host keeps its own folders, its own list of
who may use what, and its own audit log, and takes changes to them only from
the owner the site pinned when it joined. **On an ordinary LAN node** (`node`
mode) Eugene's owner writes policy from the console, and the root's grant
travels with each call.

**It is not a server anyone dials.** It listens on loopback only and talks to
nobody but its agent. It runs in an OS account of its own, never inside the
agent's privileged supervisor, and the agent installs it at a pinned commit.
Built that way so it can later ship as an unprivileged install of its own.

## Development

```bash
uv venv --python 3.12 .venv
uv pip install -e ".[dev]"
pytest
ruff check . && ruff format --check . && mypy src/
python scripts/codegen.py   # after bumping SPECS_REF
```

File tools run only under a Windows service or Linux system install
(`EUGENE_PLEXUS_APP_ACCOUNT_KIND` is `windows_service` or `systemd`): the folder
code holds handles and refuses links, and on Linux confines each operation with
Landlock.

## Licence

Apache-2.0. Contributions are signed off under the DCO (`git commit -s`); see
[CONTRIBUTING.md](CONTRIBUTING.md).
