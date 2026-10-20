# Blankas

Numbered, issuer-signed blank forms for deals between two AI agents.
Both agents fill the same fields and sign the same hash, so each keeps an identical copy.
Blankas never sees the deal content, never holds money and never needs private keys.

Pilot: the first 100 blanks are free. Lietuviškai: [README.lt.md](README.lt.md).

## Connect

| | |
| --- | --- |
| Hosted MCP server (streamable HTTP) | `https://pvl.app.n8n.cloud/mcp/blankas-mcp` |
| Local signer MCP server (stdio) | `uvx --from git+https://github.com/sirsinatoriai-png/blankas blankas-mcp` |
| HTTP API (POST `{"action": ...}`) | `https://pvl.app.n8n.cloud/webhook/blankas` |
| Spec for agents | `https://pvl.app.n8n.cloud/webhook/blankas/llms.txt` |
| Web interface | `https://pvl.app.n8n.cloud/webhook/blankas/ui` |

## Two MCP servers

**Hosted** – no setup and no keys. Tools: `blankas_info`, `blankas_spec`, `blankas_issue`,
`blankas_verify`, `blankas_mark`, `blankas_marks`. Use it to issue blanks and verify documents.

**Local signer** – runs on the agent's own machine and keeps its keys in `~/.blankas/identity.json`.
It lets any MCP agent complete a deal without writing code. Tools: `blankas_identity`, `blankas_issue`,
`blankas_prepare`, `blankas_sign`, `blankas_assemble`, `blankas_verify`, `blankas_mark`.
It can only sign Blankas deal hashes, never arbitrary data.

MCP client configuration (Claude Desktop, Cursor and others):

```json
{
  "mcpServers": {
    "blankas": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/sirsinatoriai-png/blankas", "blankas-mcp"]
    }
  }
}
```

## How a deal works

1. Each agent calls `blankas_identity` and shares its public keys.
2. One agent calls `blankas_issue` with the counterparty's public keys.
3. One agent calls `blankas_prepare` with the terms (subject, price in minor units, payment, deadline,
   sanction) and sends the blank and content unchanged to the other agent.
4. Each agent calls `blankas_sign` with exactly the same blank and content; they exchange signatures.
5. `blankas_assemble`, then `blankas_verify`. Both agents keep identical copies.

The agreed sanction is part of the signed content. Blankas does not enforce it and does not move money.

## Python

```python
from blankas_client import Client, Identity, fill, deal_hash, sign_deal, assemble

client = Client("https://pvl.app.n8n.cloud/webhook/blankas")
a, b = Identity.generate(), Identity.generate()
blank = client.issue_blank(a.public(), b.public())
content = fill(blank, subject="Dataset", price_minor=1999, currency="EUR", payment="x402 on delivery",
               deadline="2026-10-20T12:00:00Z", sanction="Full refund within 24 hours")
h = deal_hash(blank, content)
print(client.verify(assemble(blank, content, sign_deal(a, h), sign_deal(b, h))))
```

## Self-hosting and tests

`python server.py` runs the same service locally (`pip install cryptography`).
`python -m unittest` runs 21 tests; `BLANKAS_IMPL=js python -m unittest` runs them against the n8n logic.
The n8n deployment is in `n8n/`.
