# New Features

* **`safe local --raft <dir>` keeps a local vault on integrated raft storage.** OpenBao 2.7 dropped the file storage backend, so a persistent `safe local --file` vault no longer starts under `bao`. With `--raft`, safe runs a single-node raft store in the directory you name, creates that directory with mode 0700 when it is missing, and waits for the node to become active after unseal before it mounts `secret/`. The node ID is always `safe-local`, and we treat that value as a stable contract, because a raft store remembers it.

* **`safe local --raft` gains `--cluster-port`.** A raft node also listens on a cluster port, which defaults to the API port plus one. Pass `--cluster-port` to choose it yourself, for example when several local vaults run side by side. safe checks that the cluster port is free before it starts the engine and stops with a message that names the port, because a single raft node would otherwise carry on without its cluster listener and mention the problem only in its own log. The option is refused without `--raft` and when it matches `--port`.

* **`safe local` can reopen a vault with a root token you saved, through `--root-token-file <path>`.** safe reads the token from the file before it starts the engine, so the token never appears on a command line or in the engine's environment. After unseal, safe checks the token with the server and accepts it only if it carries the root policy, and it never asks the server to generate a new root token when the saved one is valid. A rejected token stops safe with `The root token in <file> was rejected by <engine>`, and a token without the root policy stops it with `The root token in <file> is not a root token`. Both messages are stable, so scripts can match on them. safe warns when the file grants any access to its group or to other users, and it refuses the option with `--memory` or with storage that is not initialized yet.

# Behavior Changes

* **`safe local` now stops its engine when it receives SIGHUP.** Closing the terminal or killing the tmux session that ran `safe local` used to end safe without stopping the engine. The engine reads SIGHUP as a request to reload its configuration, so it kept running and held the port and the data directory. safe now tears the engine down and removes its target, as it already did for Ctrl-C and SIGTERM.

* **`safe local` ignores SIGPIPE.** When its output runs through a pipe such as `tee` and the reader goes away first, safe used to die on the next write and leave the engine running. It now finishes the teardown regardless.

# OpenBao and sys/generate-root

OpenBao disables the `sys/generate-root` API by default, starting in 2.5.3, and answers it with `unsupported operation`. Without `--root-token-file`, reopening a `--file` or `--raft` vault generates a new root token through that API, so under OpenBao a reopen needs `--root-token-file`. When the API is refused, safe now says so and points at `--root-token-file`. If the root token is lost, only `--engine vault` can still generate a new one.
