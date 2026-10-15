# PocketShell client runtime

The generated `psc.mjs` is intentionally excluded from Git. It can contain upstream deployment defaults and is a runtime build artifact, not public source for this project.

The server reuses the public PocketShell client and core code. The build script pins both source commits, including the client device-login port at `655e43f`. Upstream packages declare MIT licensing. See the upstream repositories for attribution and dependency licenses.

Build with `node scripts/build-client.mjs`. A local checkout can be supplied as the first argument. The generated runtime preserves upstream host-key verification, gateway account authorization, SSH hardening and command serialization.

The same script bundles `@pocketshell/core`'s key vault (`src/keyVault`, pinned separately, with its `hash-wasm` dependency) into `key-vault.mjs` for the OAuth consent page. It also copies core's vault v1 known-answer vectors to `vault-v1-vectors.json`, which the tests check against the bundle. Both files are generated and excluded from Git.
