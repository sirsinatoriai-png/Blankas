"""Blankas – kliento biblioteka agentams (tik standartinė biblioteka + blankas_core).

Veikia su abiem versijomis, nes naudoja vieną RPC adresą:
  Client("https://pvl.app.n8n.cloud/webhook/blankas")   # n8n
  Client("http://127.0.0.1:8402")                        # python server.py
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from blankas_core import (Identity, assemble, check_receipt, deal_hash, fill, open_envelope,  # noqa: F401
                          seal_envelope, sign_deal, verify_document)


class BlankasError(Exception):
    def __init__(self, status: int, payload: dict):
        self.status, self.payload = status, payload
        super().__init__(f"{status} {payload.get('error', '')}: {payload.get('message', '')}")


class Client:
    def __init__(self, base_url: str = "http://127.0.0.1:8402", timeout: float = 30):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def _rpc(self, action: str, **params) -> dict:
        data = json.dumps({"action": action, **params}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self.base, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "blankas-client/0.2")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read())
            except ValueError:
                payload = {"error": "http", "message": str(exc)}
            raise BlankasError(exc.code, payload) from None

    def info(self) -> dict:
        return self._rpc("info")

    def issuer(self) -> str:
        return self._rpc("issuer")["issuer"]

    def issue_blank(self, party_a: dict, party_b: dict) -> dict:
        """party_a / party_b – Identity.public() rezultatai."""
        return self._rpc("issue", party_a=party_a, party_b=party_b)["blank"]

    def verify(self, document: dict) -> dict:
        return self._rpc("verify", document=document)

    def mark(self, document: dict) -> dict:
        """Žyma: serveris mato tik blanko numerį, hash ir abu parašus."""
        return self._rpc("mark", **_proof(document))["mark"]

    def marks(self, blank_id: str) -> list[dict]:
        return self._rpc("marks", blank_id=blank_id)["marks"]

    def deposit(self, document: dict, envelope: dict) -> dict:
        """Padeda užšifruotą voką. Grąžina {'ticket': ..., 'token': ...}."""
        return self._rpc("deposit", **_proof(document), envelope=envelope)

    def retrieve(self, envelope_id: str, token: str) -> dict:
        return self._rpc("retrieve", envelope_id=envelope_id, token=token)

    def delete(self, envelope_id: str, token: str) -> dict:
        return self._rpc("delete", envelope_id=envelope_id, token=token)


def _proof(document: dict) -> dict:
    return {"blank": document["blank"], "deal_hash": document["deal_hash"], "signatures": document["signatures"]}
