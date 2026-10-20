#!/usr/bin/env python3
"""Blankas – vietinis MCP serveris (stdio), kuris saugo agento raktus ir pasirašo sandorius.

Privatūs raktai lieka šiame kompiuteryje (~/.blankas/identity.json) ir niekada neperduodami.
Įrankis gali pasirašyti tik Blanko sandorio hash, o ne bet kokius duomenis.

MCP kliento komanda:  blankas-mcp   (arba: python blankas_mcp.py)
Nustatymai:  BLANKAS_URL  – API adresas (numatyta – gyva n8n versija)
             BLANKAS_HOME – raktų aplankas (numatyta – ~/.blankas)
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import blankas_core as core
from blankas_client import BlankasError, Client

DEFAULT_URL = "https://pvl.app.n8n.cloud/webhook/blankas"
PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "blankas-signer", "version": "0.1.0"}
INSTRUCTIONS = (
    "Local Blankas signer: this agent's private keys stay on this machine. Deal flow: "
    "1) blankas_identity, then share the public keys with the counterparty; "
    "2) one party calls blankas_issue; 3) one party calls blankas_prepare and sends blank + content unchanged to the other; "
    "4) each party calls blankas_sign with exactly the same blank + content and they exchange signatures; "
    "5) blankas_assemble, then blankas_verify. Show the deal terms to your principal before signing."
)

_OBJ = {"type": "object"}
_KEYS = {"type": "object", "properties": {"sign": {"type": "string"}, "box": {"type": "string"}},
         "required": ["sign", "box"], "description": "Public keys: sign (Ed25519) and box (X25519), base64url"}
TOOLS = [
    {"name": "blankas_identity",
     "description": "Show this agent's public keys (created on first use). Share them with the counterparty. "
                    "Private keys never leave this machine.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "blankas_issue",
     "description": "Get a new numbered blank for a deal between this agent and a counterparty. Uses one free blank.",
     "inputSchema": {"type": "object", "properties": {
         "counterparty": _KEYS,
         "my_role": {"type": "string", "enum": ["a", "b"], "description": "This agent's role on the blank, default a"}},
         "required": ["counterparty"]}},
    {"name": "blankas_prepare",
     "description": "Fill the deal terms on a blank (adds a random salt). Send the returned blank and content unchanged "
                    "to the counterparty so both sign exactly the same terms.",
     "inputSchema": {"type": "object", "properties": {
         "blank": {**_OBJ, "description": "Blank as returned by blankas_issue"},
         "subject": {"type": "string", "description": "What is delivered"},
         "price_minor": {"type": "integer", "description": "Price in minor units, e.g. cents: 1999 = 19.99"},
         "currency": {"type": "string", "description": "Currency code, e.g. EUR or USDC"},
         "payment": {"type": "string", "description": "How and when payment is made"},
         "deadline": {"type": "string", "description": "Agreed deadline, ISO 8601 recommended"},
         "sanction": {"type": "string", "description": "Agreed sanction if the obligation is not met"},
         "version": {"type": "integer", "description": "Version, default 1; the highest co-signed version wins"},
         "check": {"type": "string", "description": "Optional: how fulfilment is verified"},
         "arbiter": {"type": "string", "description": "Optional: who resolves disputes"},
         "notes": {"type": "string", "description": "Optional notes"}},
         "required": ["blank", "subject", "price_minor", "currency", "payment", "deadline", "sanction"]}},
    {"name": "blankas_sign",
     "description": "Sign the deal hash of a blank + content with this agent's key. Checks the blank and the terms first "
                    "and returns the signed terms so they can be confirmed.",
     "inputSchema": {"type": "object", "properties": {"blank": _OBJ, "content": _OBJ}, "required": ["blank", "content"]}},
    {"name": "blankas_assemble",
     "description": "Combine blank, content and both signatures into the final document and verify it locally. "
                    "Both parties keep identical copies.",
     "inputSchema": {"type": "object", "properties": {
         "blank": _OBJ, "content": _OBJ,
         "signatures": {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
                        "required": ["a", "b"]}},
         "required": ["blank", "content", "signatures"]}},
    {"name": "blankas_verify",
     "description": "Verify a completed document locally and with the Blankas service. Free.",
     "inputSchema": {"type": "object", "properties": {"document": _OBJ}, "required": ["document"]}},
    {"name": "blankas_mark",
     "description": "Register a timestamped mark that both parties signed this deal hash. The service sees only the hash.",
     "inputSchema": {"type": "object", "properties": {"document": _OBJ}, "required": ["document"]}},
]
TOOL_NAMES = {tool["name"] for tool in TOOLS}


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class Signer:
    def __init__(self, url: str | None = None, home: str | None = None):
        self.client = Client(url or os.environ.get("BLANKAS_URL") or DEFAULT_URL)
        self.home = Path(home or os.environ.get("BLANKAS_HOME") or Path.home() / ".blankas")
        self._issuer: str | None = None

    def identity(self) -> core.Identity:
        path = self.home / "identity.json"
        if path.exists():
            return core.Identity.load(str(path))
        self.home.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.home, 0o700)
        except OSError:
            pass
        identity = core.Identity.generate()
        identity.save(str(path))
        return identity

    def issuer(self) -> str:
        if not self._issuer:
            self._issuer = self.client.issuer()
        return self._issuer

    def my_role(self, blank: dict) -> str:
        me = self.identity().public()["sign"]
        parties = blank.get("parties", {}) if isinstance(blank, dict) else {}
        for role in ("a", "b"):
            if isinstance(parties.get(role), dict) and parties[role].get("sign") == me:
                return role
        raise ValueError("This agent is not a party to this blank: its public key is not on it")

    def _checked(self, blank, content=None) -> None:
        errors = core.check_blank(blank, self.issuer())
        if content is not None:
            errors += core.check_content(content)
        if errors:
            raise ValueError("; ".join(errors))

    # ---------------------------------------------------------------- įrankiai

    def t_identity(self, args: dict) -> dict:
        return {"public_keys": self.identity().public(),
                "note": "Share these public keys with the counterparty. Private keys never leave this machine."}

    def t_issue(self, args: dict) -> dict:
        role = args.get("my_role", "a")
        if role not in ("a", "b"):
            raise ValueError("my_role must be 'a' or 'b'")
        me = self.identity().public()
        counterparty = args["counterparty"]
        party_a, party_b = (me, counterparty) if role == "a" else (counterparty, me)
        return {"blank": self.client.issue_blank(party_a, party_b), "my_role": role}

    def t_prepare(self, args: dict) -> dict:
        blank = args["blank"]
        self._checked(blank)
        price = args["price_minor"]
        if isinstance(price, float) and price.is_integer():
            price = int(price)
        if not isinstance(price, int) or isinstance(price, bool):
            raise ValueError("price_minor must be an integer in minor units, e.g. 1999 for 19.99")
        version = args.get("version", 1)
        if isinstance(version, float) and version.is_integer():
            version = int(version)
        content = core.fill(blank, subject=args["subject"], price_minor=price, currency=args["currency"],
                            payment=args["payment"], deadline=args["deadline"], sanction=args["sanction"],
                            version=version, check=args.get("check"), arbiter=args.get("arbiter"),
                            notes=args.get("notes"))
        return {"blank": blank, "content": content, "deal_hash": core.deal_hash(blank, content),
                "next": "Send blank and content unchanged to the counterparty; both parties call blankas_sign with them."}

    def t_sign(self, args: dict) -> dict:
        blank, content = args["blank"], args["content"]
        self._checked(blank, content)
        role = self.my_role(blank)
        dhash = core.deal_hash(blank, content)
        terms = {k: content[k] for k in ("subject", "price", "payment", "deadline", "sanction") if k in content}
        return {"role": role, "deal_hash": dhash, "signature": core.sign_deal(self.identity(), dhash),
                "signed_terms": terms,
                "next": "Send the signature to the counterparty, then call blankas_assemble with both signatures."}

    def t_assemble(self, args: dict) -> dict:
        signatures = args["signatures"]
        document = core.assemble(args["blank"], args["content"], signatures["a"], signatures["b"])
        return {"document": document, "verification": core.verify_document(document, self.issuer())}

    def t_verify(self, args: dict) -> dict:
        document = args["document"]
        return {"local": core.verify_document(document, self.issuer()), "service": self.client.verify(document)}

    def t_mark(self, args: dict) -> dict:
        return {"mark": self.client.mark(args["document"])}


def handle(signer: Signer, msg: dict) -> dict:
    method = msg.get("method")
    params = msg.get("params") or {}
    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[1]
        return {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = params.get("name")
        if name not in TOOL_NAMES:
            raise RpcError(-32602, f"Unknown tool: {name}")
        tool = getattr(signer, "t_" + name.removeprefix("blankas_"))
        try:
            result = tool(params.get("arguments") or {})
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}],
                    "isError": False}
        except KeyError as exc:
            text = f"Missing argument: {exc.args[0]}"
        except BlankasError as exc:
            text = f"Blankas service error {exc.status}: {exc.payload.get('message', '')}"
        except (ValueError, TypeError) as exc:
            text = f"Error: {exc}"
        return {"content": [{"type": "text", "text": text}], "isError": True}
    raise RpcError(-32601, f"Method not found: {method}")


def respond(signer: Signer, msg) -> dict | None:
    if not isinstance(msg, dict) or "id" not in msg:
        return None  # pranešimai (notifications) atsakymo nereikalauja
    try:
        return {"jsonrpc": "2.0", "id": msg["id"], "result": handle(signer, msg)}
    except RpcError as exc:
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": exc.code, "message": exc.message}}
    except Exception as exc:  # noqa: BLE001 – klientui grąžinama klaida, serveris toliau veikia
        print(f"blankas-mcp: {exc!r}", file=sys.stderr)
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": "Internal error"}}


def _write(obj) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main() -> None:
    signer = Signer()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        if isinstance(msg, list):
            replies = [r for r in (respond(signer, m) for m in msg) if r is not None]
            if replies:
                _write(replies)
        else:
            reply = respond(signer, msg)
            if reply is not None:
                _write(reply)


if __name__ == "__main__":
    main()
