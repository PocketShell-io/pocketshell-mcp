# Security and limits

OAuth connector tokens are separate from upstream device credentials. The server binds authorization codes to the registered client, exact redirect, S256 challenge and MCP resource. Codes expire after one minute and can be exchanged once. Access tokens last up to one hour; refresh grants last at most 30 days and never outlive the upstream session. Refresh rotation detects reuse and revokes the connector grant. Reconnect through device approval when the upstream session expires.

The server checks upstream account validity on every MCP request. Revoking the PocketShell or DataOps device session blocks subsequent tool requests, including when a connector still holds an unexpired local token. Revocation cannot undo an already running host operation. OAuth registration does not authenticate a client brand: the consent screen displays the client name as unverified input and shows its exact callback address.

SQLite values, including upstream credentials and administrator SSH profiles, use AES-256-GCM with record-bound authenticated data. OAuth bearer lookup keys are hashes. The database file is mode 0600 in a service-owned mode-0700 directory. Storage keys come from protected runtime configuration. Each service needs its own key and database. Backups must preserve their pairing.

PocketShell executes the shared `psc` runtime in a separate process and private temporary configuration directory for each call. Credentials, SSH identity and pins use mode-0600 temporary files. The service deletes them after the call. Production places the runtime directory on ephemeral `/run` storage. The existing client enforces public-key SSH authentication, strict independently verified host pins and gateway account ownership. No model tool changes trust or exposes a local shell on the server.

Hosting an SSH client on the gateway adds a credential-bearing service to that machine. Separate Unix users protect MCP credentials from the ordinary gateway process. A root compromise can access them. Keep the runtime unprivileged, deny instance metadata, protect releases from service-user writes and use the existing deployment controls.

With `MCP_VAULT=on`, SSH private keys come from the user's end-to-end encrypted key vault. The passphrase, the Argon2id master key and the vault data key stay in the consent page. The page decrypts only the keys for the hosts the user ticks and sends them over TLS, bound to the consent transaction's cookie, CSRF token and same-origin check. The server keeps them in process memory only, keyed by OAuth grant. They are never written to the encrypted store, logs, tool errors or temporary files: a per-call private `ssh-agent` receives each key on stdin with a lifetime bounded by the call. The keys are wiped when the TTL (default 8 hours) or grant expires, after 30 minutes without a tool call (configurable), on token revocation, on refresh-token reuse, when the upstream session stops validating, and on restart. Key objects redact themselves from inspection and serialization. The unlock page is the only page that runs script: same-origin files only, plus WebAssembly for Argon2id. While keys are unlocked, the MCP client and anything able to drive it can use them for the unlocked hosts. Unlock only hosts the assistant needs and revoke the connection when done. Operating-system memory protection is the remaining boundary: a root compromise or memory dump of the service can expose unlocked keys, so keep core dumps disabled for the service.

With the vault enabled, the service refuses to start with inspector or heap-snapshot options (on the command line or in `NODE_OPTIONS`) and requires `node --disable-sigusr1`, so a signal cannot attach a debugger to unlocked keys. Run it under systemd with at least:

```ini
[Service]
ExecStart=/usr/bin/node --disable-sigusr1 /opt/pocketshell-mcp/src/main.mjs
Environment=NODE_OPTIONS=
User=pocketshell-mcp
UMask=0077
LimitCORE=0
MemorySwapMax=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
StateDirectory=pocketshell-mcp
StateDirectoryMode=0700
RuntimeDirectory=pocketshell-mcp
RuntimeDirectoryMode=0700
```

`LimitCORE=0` stops crash dumps from writing the heap to disk, and `MemorySwapMax=0` (cgroup v2) keeps it out of swap. The per-call `ssh-agent` also marks itself non-dumpable. `MemoryDenyWriteExecute` is incompatible with the V8 JIT. Also keep `kernel.yama.ptrace_scope` at 1 or higher, so other processes of the service user cannot read its memory.

MCP requests are capped at 128 KiB; upstream and tool results at 1 MiB. At most eight MCP requests execute concurrently per service. OAuth endpoints allow 60 requests per minute per source and MCP allows 120. PocketShell child calls have a 45-second bound; the gateway proxy has a 55-second bound. Use `start` followed by `status`/`capture` for longer work. Avoid retrying writes until their outcome is known.

The service implements modern Streamable HTTP with JSON responses. It does not expose a separate legacy SSE endpoint or a public stdio process. Clients must support standard discovery, DCR and authorization code with S256 PKCE. Client metadata documents are not advertised; choose automatic registration where a client offers both. An operator can restrict callbacks through configuration. If the user leaves the unlock step unfinished, the expired transaction's upstream device session is revoked rather than left valid. The consent page offers a read-only connection. Its grant is offered only tools annotated as read-only, and the server refuses any other tool call for that grant, so a prompt-injected or misbehaving client cannot start, send to or stop sessions, or write DataOps records. Browser consent is protected by a transaction cookie, same-origin POST and CSRF token. Pages use `Referrer-Policy: same-origin`, so browsers send the real `Origin` on consent POSTs, and each consent page's CSP `form-action` allows only its own validated callback origin. Tool results and terminal output are untrusted data.
