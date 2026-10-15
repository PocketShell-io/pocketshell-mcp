# Service configuration

All examples are placeholders. Supply deployment addresses and account information through private runtime configuration.

| Variable | Meaning |
| --- | --- |
| `MCP_SERVICE` | `pocketshell` or `dataops` |
| `MCP_ISSUER` | Public HTTPS origin, optionally followed by a single service path; no trailing slash |
| `MCP_UPSTREAM_ORIGIN` | PocketShell broker origin or DataOps portal origin |
| `MCP_WEB_ORIGIN` | Trusted device-approval web origin |
| `MCP_GATEWAY_ORIGIN` | PocketShell gateway HTTPS origin; PocketShell only |
| `MCP_ALLOWED_EMAILS` | Required comma-separated allowlist of upstream-verified account emails |
| `MCP_REDIRECT_URIS` | Optional exact callback allowlist; unset accepts standard HTTPS and HTTP-loopback DCR callbacks |
| `MCP_STORAGE_KEY_FILE` | Preferred: path to a protected file containing a 32-byte hexadecimal encryption key |
| `MCP_STORAGE_KEY` | Alternative hexadecimal storage key supplied by the secret manager |
| `MCP_STATE_DIR` | Private mode-0700 persistent directory for encrypted SQLite state |
| `MCP_BIND`, `PORT` | Private listening address and port; defaults to loopback and port 8080 |
| `MCP_VAULT` | PocketShell only: `on` takes SSH keys from the user's key vault, unlocked during consent, instead of the profile `privateKey`; default off |
| `MCP_VAULT_TTL_SECONDS` | How long unlocked vault keys stay in memory; default 28800 (8 hours), 60 to 2592000, never longer than the grant |
| `MCP_VAULT_IDLE_SECONDS` | Drop a grant's unlocked keys after this long without a tool call; default 1800 (30 minutes), 60 to the TTL |

For example, use `https://mcp.example.com` for PocketShell and `https://mcp.example.com/dataops` for DataOps. Their MCP resources are `/mcp` and `/dataops/mcp`. The server advertises the correct discovery addresses for either path.

No service address, account email, SSH identity or host pin is built into the public project. Preserve the storage key when updating configuration. Back up the encrypted store and its key through the managed secret and backup systems; losing the key loses access to stored grants and SSH profiles.

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

With the vault enabled, the profile carries only `hosts` and `pins`; provision it with `MCP_VAULT=on` set and without `privateKey`. Host `name`s must match the account host aliases that the vault binds keys to. After device approval, the consent page asks for the account vault passphrase. The browser derives the vault key and decrypts the index locally, then lists the profile hosts. Only the keys of the hosts the user ticks are decrypted and sent to the server, which holds them in process memory for the grant. Hosts bound to a password entry cannot be used, because MCP SSH is public-key only. "Continue without keys" completes the connection with every SSH tool locked.

The server reads vault ciphertext through the broker's CLI-bearer routes (`GET /cli/settings/{slot}`) with the user's own device session. When the phase-2 verifier is deployed, it calls `POST /cli/vault/verify` before reading key blobs. Tools on a host without an unlocked key return `vault locked: re-authorize to unlock`; reconnecting the connector unlocks again. The `hosts` tool reports which hosts are unlocked and when the keys expire. Each call loads its key into a private per-call `ssh-agent` on stdin, and `ssh` receives only the public key file. The private key is never written to a file.

The assistant has no profile-editing, pin-replacement, arbitrary SSH destination, local-host or local-file tool. Gateway discovery only reports devices; an advertised host key never becomes a trusted pin.
