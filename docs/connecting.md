# Add a connector

Use the deployed public HTTPS URL supplied by the operator. The examples below use `https://mcp.example.com/mcp`. One connection covers every registered CLI: `pocketshell` and `dataops`, plus a `catalog` tool that lists them. The URL must be reachable from the assistant provider's servers, with a trusted certificate.

Every client follows the same sign-in sequence:

1. Discover OAuth metadata and register automatically with DCR.
2. Open the authorization page and inspect the client callback address and requested access.
3. Choose **Continue to device approval**, open the approval link, and approve the displayed code in the existing PocketShell account.
4. Return to the connector authorization tab and choose **Finish connection**.
5. Optionally connect other CLI accounts on the same page. For a device-flow CLI (DataOps), choose **Connect \<cli\> as a gateway device** and approve the new device, which is named after the assistant (for example "MCP gateway, ChatGPT"). For a token CLI (AISL), paste its token into the password field there. Choose **Continue** to skip any of them. The browser returns to the assistant, and the client completes its PKCE exchange.

To connect a CLI later, ask the assistant to call that CLI's tool with `connect`; a tool call for an unconnected CLI also returns this link. Open the link in a browser and approve a one-time device in your primary account. That device is revoked immediately and only proves you own this connection. Then connect the CLI as in step 5. The link works once and expires after 10 minutes.

No bearer token, API key, SSH key or pin is pasted into the assistant.

## ChatGPT and dots

1. On ChatGPT web, open **Plugins** → plus → **Add custom MCP server**.
2. Enter a name such as `mcp-hub` and the full MCP URL `https://mcp.example.com/mcp`. Select **OAuth** and automatic/dynamic client registration. Leave static client credentials empty.
3. Review the warning and choose **Create as a plugin**. Complete the sign-in sequence above when prompted.
4. Install the resulting plugin. In a new conversation, type `@` and select it. For dots, enable the installed plugin for the account/dot and ask it to call `catalog` explicitly.
5. Check the discovered tools, connected account and write-approval settings. Start with `catalog`, then `dataops` with `["help"]`, then a read such as `["tasks", "list", "--mine"]` (DataOps account must be connected first). Use a disposable session for an authorized write test.

Some interfaces still use **Settings → Apps/Connectors → Advanced → Developer mode**. Creation and write access depend on account rollout, workspace permissions and security restrictions. If the custom-server entry is unavailable, an account/workspace administrator must resolve access. Refresh the connection after changing tool metadata.

Sources: [custom MCP setup](https://developers.openai.com/api/docs/guides/custom-mcp-server), [dots app access](https://learn.chatgpt.com/docs/dots/computers-and-apps).

## Grok Bot

In the Bot's chat, ask: “Add a custom MCP server named mcp-hub, type Remote HTTPS, at `https://mcp.example.com/mcp`, using OAuth and automatic registration.” Confirm the setup card, authenticate through the browser, then attach the connector with `@` and request `catalog`.

Use **Remote HTTPS** so authorization stays in the connector service rather than a command on the Bot computer. Installed connectors are account-wide. A Team Bot using OAuth requires each teammate's own sign-in. A grok.com connector and a Grok Bot connector are separate surfaces; test the Bot itself.

Sources: [Grok Bot app connections](https://docs.x.ai/grok-bot/computer-and-apps), [Team Bot remote MCP authentication](https://docs.x.ai/grok-bot/team-bots), [Cursor staff instructions for custom Bot connectors](https://forum.cursor.com/t/grokbot-custom-connectors/169965/5).

## Claude web and Desktop

Open **Customize → Connectors → Add custom connector**, enter the name `mcp-hub` and URL `https://mcp.example.com/mcp`, choose sign-in, and select **Register automatically** as the OAuth client method. Finish authorization and enable the connector for the conversation. Team/Enterprise owners may need to add it to the organization first. Desktop remote connectors also connect from the provider cloud.

Source: [Claude custom connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

## Claude Code

```sh
claude mcp add --transport http mcp-hub https://mcp.example.com/mcp
```

Open `/mcp`, select the server and authenticate. Source: [Claude Code MCP](https://code.claude.com/docs/en/mcp).

## Cursor

Add a remote HTTP server in the MCP settings, or add this configuration to the MCP configuration file:

```json
{"mcpServers":{"mcp-hub":{"url":"https://mcp.example.com/mcp"}}}
```

Choose Connect/Authenticate and finish browser authorization. No Authorization header belongs in the configuration. Source: [Cursor MCP](https://cursor.com/docs/mcp).

## Codex

```sh
codex mcp add mcp-hub --url https://mcp.example.com/mcp
codex mcp login mcp-hub --oauth-client-registration dcr
```

Finish browser approval. Source: [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp).

## MCP Inspector

Run `npx @modelcontextprotocol/inspector` and select its web interface, HTTP transport and `https://mcp.example.com/mcp`. Use the OAuth controls to discover metadata, register and authorize; follow the same browser steps. Run **List Tools** (expect `catalog`, `pocketshell`, `dataops`, `dapier`, `aisl`), inspect schemas/annotations, then call `catalog` and a DataOps read such as `dataops` with `{"argv": ["tasks", "list", "--mine"]}`. Do not paste an existing application token or disable TLS verification.

`npm test` also runs Inspector's CLI over trusted HTTPS against the multiplexed gateway, including DCR/PKCE and a synthetic device-approval bridge. It lists `catalog` and `dataops` with schema checks, calls `catalog`, and exercises a DataOps read through the real manifest argv mapping. The synthetic upstream does not prove a real account or deployed endpoint works.

## Record acceptance separately

For each client, record the deployed revision, client name/version, DCR/PKCE result, read call result, reconnect/refresh result and upstream-revoke result. ChatGPT/dots and Grok Bot must pass on their actual accounts before production acceptance; Claude and Inspector are additional interoperability targets. Do not substitute local protocol tests for these results.
