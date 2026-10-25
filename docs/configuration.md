# Service configuration

All examples are placeholders. Supply deployment addresses and account information through private runtime configuration.

| Variable | Meaning |
| --- | --- |
| `MCP_SERVICE` | Optional; only `gateway` (or legacy `pocketshell`). Other CLIs are registered, not run as separate services |
| `MCP_ISSUER` | Public HTTPS origin, optionally followed by a single service path; no trailing slash |
| `MCP_UPSTREAM_ORIGIN` | PocketShell broker origin (the primary login) |
| `MCP_WEB_ORIGIN` | Trusted device-approval web origin |
| `MCP_GATEWAY_ORIGIN` | PocketShell gateway HTTPS origin |
| `MCP_RUNTIME_DIR` | Private directory for per-call worker homes; default `/run/pocketshell-mcp` |
| `MCP_DATAOPS_ORIGIN` | Enables the `dataops` tool against this portal origin (device flow) |
| `MCP_DATAOPS_WEB_ORIGIN` | Optional DataOps device-approval origin; defaults to `MCP_DATAOPS_ORIGIN` |
| `MCP_DATAOPS_ENTRYPOINT` | Optional absolute path of the built DataOps CLI; defaults to `vendor/dataops.mjs` |
| `MCP_CLI_CONFIG_FILE` | Optional operator-only JSON file registering more CLIs; see below |
| `MCP_ALLOWED_EMAILS` | Required comma-separated allowlist of upstream-verified account emails |
| `MCP_REDIRECT_URIS` | Optional exact callback allowlist; unset accepts standard HTTPS and HTTP-loopback DCR callbacks |
| `MCP_STORAGE_KEY_FILE` | Preferred: path to a protected file containing a 32-byte hexadecimal encryption key |
| `MCP_STORAGE_KEY` | Alternative hexadecimal storage key supplied by the secret manager |
| `MCP_STATE_DIR` | Private mode-0700 persistent directory for encrypted SQLite state |
| `MCP_BIND`, `PORT` | Private listening address and port; defaults to loopback and port 8080 |
| `MCP_VAULT` | PocketShell only: `on` takes SSH keys from the user's key vault, unlocked during consent, instead of the profile `privateKey`; default off |
| `MCP_VAULT_TTL_SECONDS` | How long unlocked vault keys stay in memory; default 28800 (8 hours), 60 to 2592000, never longer than the grant |
| `MCP_VAULT_DEDICATED_ORIGIN` | Required with `MCP_VAULT=on`: the issuer's origin, repeated to confirm that nothing else (no DataOps, no other app) is served on it |
| `MCP_VAULT_IDLE_SECONDS` | Drop a grant's unlocked keys after this long without a tool call; default 1800 (30 minutes), 60 to the TTL |

For example, with `https://mcp.example.com` the MCP resource is `https://mcp.example.com/mcp`. The server advertises the correct discovery addresses for an optional single service path.

No service address, account email, SSH identity or host pin is built into the public project. Preserve the storage key when updating configuration. Back up the encrypted store and its key through the managed secret and backup systems; losing the key loses access to stored grants and SSH profiles.

## Registered CLIs (`MCP_CLI_CONFIG_FILE`)

A JSON array, at most 16 entries. Each entry registers one CLI tool:

```json
[{
  "manifestFile": "/etc/pocketshell-mcp/manifests/example.json",
  "command": "/opt/example/bin/example",
  "prefix": [],
  "mounts": ["/opt/example"],
  "origin": "https://cli.example.com",
  "originEnv": "EXAMPLE_URL",
  "auth": { "type": "token", "tokenEnv": "EXAMPLE_TOKEN" }
}]
```

`command` is an absolute executable, never a shell. `mounts` are read-only paths the sandbox needs. The CLI always receives the fixed `origin`, and no call can choose another one. The manifest is the reviewed command allowlist. See `manifests/` for examples.

### Auth types

| `auth.type` | Linking | Injected into the worker |
| --- | --- | --- |
| `token` | The user pastes a token or API key once on the gateway's HTTPS page | `tokenEnv`, and/or `env` and `files` templates |

DataOps (`MCP_DATAOPS_ORIGIN`) and PocketShell (the primary login) use built-in device flows.

Token options:

- `tokenEnv`: an environment variable set to the token.
- `env`: `{ "NAME": "Token {token}" }` templates.
- `files`: `{ "example/config.json": { "token": "{token}", "url": "{origin}" } }`. Each path is relative to the worker's private `HOME`, which is also `XDG_CONFIG_HOME`. A string value is written as is; any other JSON value is serialized.
- `validate`: `{ "path": "/api/me", "scheme": "Token" }` checks the token against the fixed origin before storing it.
- `lifetimeDays`: how long the stored copy is kept; default 30.

At least one of `tokenEnv`, `env` or `files` must use `{token}`. Disconnecting removes the gateway's encrypted copy. Revoke the token upstream separately.

To add an auth type, call `registerAuthType(name, { config, create })` from `src/auth.mjs`. `config` is a strict zod schema for the `auth` block. `create` returns:

- `auth`, the linking plugin: either a device plugin with `start`, `poll`, `revoke` and optional `identity`, or a token plugin with `accept` and `revoke`.
- `materialize(credential)`, which returns the `{ environment, files }` the CLI expects.

The config loader and browser pages need no change.

## PocketShell SSH profile

A human administrator provisions a profile after verifying host keys independently and enrolling an SSH client public key using PocketShell's normal host setup. The profile is JSON supplied on stdin:

```json
{
  "hosts": [{"name": "example-host", "deviceId": "example-device", "user": "example-user"}],
  "privateKey": "<dedicated SSH private key from secure storage>",
  "pins": "<complete known_hosts lines verified independently on each host>"
}
```

Run `node scripts/provision-profile.mjs <account-email>` as the service user with the same state directory and storage-key credential, redirecting the private JSON file into stdin. Do not use an argument for secret content. The profile is encrypted in the state database. This is administrator provisioning, not a connector user's login step.

## PocketShell key vault (`MCP_VAULT=on`)

Vault mode needs its own origin, for example `https://pocketshell-mcp.example.com` with no service path. Do not serve DataOps or anything else on it: any script on the same origin could read the passphrase typed into the unlock page. The service refuses to start unless `MCP_ISSUER` is a bare origin and `MCP_VAULT_DEDICATED_ORIGIN` repeats it. The consent page runs `@pocketshell/core`'s key vault implementation. `node scripts/build-client.mjs` bundles it from a pinned core commit into `vendor/key-vault.mjs`, and the service refuses to start with the vault enabled when the bundle is missing. With the vault enabled, the profile carries only `hosts` and `pins`; provision it with `MCP_VAULT=on` set and without `privateKey`. Host `name`s must match the account host aliases that the vault binds keys to. After device approval, the consent page asks for the account vault passphrase. The browser derives the vault key and decrypts the index locally, then lists the profile hosts. Only the keys of the hosts the user ticks are decrypted and sent to the server, which holds them in process memory for the grant. Hosts bound to a password entry cannot be used, because MCP SSH is public-key only. "Continue without keys" completes the connection with every SSH tool locked.

The server reads vault ciphertext through the broker's CLI-bearer routes (`GET /cli/settings/{slot}`) with the user's own device session. When the phase-2 verifier is deployed, it calls `POST /cli/vault/verify` before reading key blobs. Tools on a host without an unlocked key return `vault locked: re-authorize to unlock`; reconnecting the connector unlocks again. The `hosts` tool reports which hosts are unlocked and when the keys expire. Each call loads its key into a private per-call `ssh-agent` on stdin, and `ssh` receives only the public key file. The private key is never written to a file.

The assistant has no profile-editing, pin-replacement, arbitrary SSH destination, local-host or local-file tool. Gateway discovery only reports devices; an advertised host key never becomes a trusted pin.
