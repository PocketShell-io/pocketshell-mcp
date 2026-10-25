# MCP hub

> **Retired 2026-10-26 (archived, read-only).** This MCP hub (`mcp.dtcdev.click/mcp`) is no longer deployed.
> DataOps tools now live in the dedicated DataOps MCP in the [dataops repo](https://github.com/DataTalksClub/dataops) (`mcp/`, tools `dataops_read`/`dataops_write`/`dataops_guide`),
> deployed by the DataOps pipeline: `https://frzdkakcapcyf6ywflhieyimgu0vtclr.lambda-url.eu-west-1.on.aws/mcp` (the `McpUrl` output of the `dataops-v1` stack; DataOps bearer auth).
> Dapier and AISL namespaces were removed; the PocketShell MCP tools are not needed. Last commit with all four namespaces: `ca2eca6`. Intake F10 (78b95a1b).

One generic MCP server for every registered CLI, at one public HTTPS `/mcp` endpoint. Assistant computers need no saved CLI login, SSH key or host pins. A persistent service holds that state and connects through the existing PocketShell gateway front door.

The server uses standard Streamable HTTP and MCP OAuth: discovery, dynamic client registration, authorization code with S256 PKCE, audience binding, short access tokens and rotating refresh tokens. It has no ChatGPT-specific transport or token exchange. The same endpoint can be connected by ChatGPT/dots, Claude, Grok Bot, Cursor, Codex and other OAuth-capable MCP clients.

**Status:** deployed to its public endpoint; protocol tests and Inspector HTTPS tests pass (including a multiplexed-gateway Inspector run for DataOps tools). Live discovery, DCR, consent page and real device-start flows are verified for PocketShell and DataOps. (Dapier and AISL namespaces were removed on 2026-10-26, intake F10.) Actual ChatGPT/dots, Claude and Grok Bot account tests remain required: the first browser approval and CLI linking need the operator. Protocol compatibility is not a claim that those account tests have passed.

## Tools

One gateway serves every registered CLI. Instead of one MCP tool per subcommand (roughly 100 definitions), it exposes `catalog` plus one short tool per CLI, for example `pocketshell` and `dataops`. Each CLI tool takes CLI-like `argv` (an array, never a shell string):

| Call | Result |
| --- | --- |
| `argv: []` or `["help"]` | The CLI's description, its command groups and top-level commands |
| `["help", "tasks"]` | Only the next level below `tasks` |
| `["help", "tasks", "create"]` | That command's JSON schema, scope and read/write classification |
| `["tasks", "list", "--mine"]` | Runs a reviewed, allowlisted command |
| `["connect"]` | A single-use browser link that connects this CLI's account |

Every command comes from a reviewed manifest with a closed argument schema, its own OAuth scope and a read, write or destructive classification. Writes return `approvalRequired` until the call repeats with `approved: true`. Read-only connections never receive write scopes.

PocketShell operations invoke the same `psc` runtime used by the terminal client. Account/device/gateway functions come from `@pocketshell/tui-client/core`. The public entry point lives in the upstream client package; it re-exports the existing implementations. The lower-level host contract remains in `@pocketshell/core`. The build pins both upstream source revisions. Generated bundles stay outside Git because upstream defaults can contain deployment details.

Other CLIs run their own executables in a fresh, sandboxed per-call worker that receives only that user's credential for that CLI. Each CLI has a pluggable auth type. For device-flow CLIs, the gateway logs in as its own device, labelled with the assistant's name. For token CLIs, the user pastes the token once on the gateway's HTTPS page. Credentials never pass through chat.

## Development

Requires Node 24, npm, Git and OpenSSL for the HTTPS tests. SSH operations also require OpenSSH.

```sh
npm ci
node scripts/build-client.mjs
node scripts/build-dataops.mjs
npm test
```

The build downloads pinned public client/core sources into a temporary directory, compiles the shared code, and removes the sources. To use an existing checkout, pass its path as the first argument.

Configure the gateway using the variables in [configuration](docs/configuration.md), then run `npm start`. Infrastructure belongs in the infrastructure repository; this repository does not create AWS resources.

See [connection steps](docs/connecting.md) for ChatGPT/dots, Claude, Grok Bot, Cursor, Codex and Inspector. [Security and limits](docs/security.md) describes credential storage, host trust and operating limits.
