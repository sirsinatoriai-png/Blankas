#!/usr/bin/env python3
"""Blankas – blankų išdavėjas agentų sandoriams (pilotas).

Paleidimas:  python server.py
Nustatymai per aplinkos kintamuosius (žr. README.md).
Priklausomybė: tik `cryptography`; HTTP serveris ir SQLite – iš Python standartinės bibliotekos.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blankas_core as core

MAX_BODY = 1_000_000  # baitų vienai užklausai

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS marks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, blank_id TEXT NOT NULL, deal_hash TEXT NOT NULL,
  receipt TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS envelopes (
  id TEXT PRIMARY KEY, blank_id TEXT NOT NULL, token_hash TEXT NOT NULL,
  body TEXT NOT NULL, ticket TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS marks_blank ON marks(blank_id);
CREATE INDEX IF NOT EXISTS envelopes_blank ON envelopes(blank_id);
"""


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8402
    db_path: str = "blankas.db"
    key_path: str = "issuer_key.pem"
    free_quota: int = 100
    ttl_seconds: int = 72 * 3600
    max_envelope_bytes: int = 64 * 1024
    max_marks_per_blank: int = 10
    max_envelopes_per_blank: int = 3

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ.get
        return cls(
            host=env("BLANKAS_HOST", "127.0.0.1"),
            port=int(env("BLANKAS_PORT", "8402")),
            db_path=env("BLANKAS_DB", "blankas.db"),
            key_path=env("BLANKAS_KEY_FILE", "issuer_key.pem"),
            free_quota=int(env("BLANKAS_FREE_QUOTA", "100")),
            ttl_seconds=int(env("BLANKAS_TTL_SECONDS", str(72 * 3600))),
            max_envelope_bytes=int(env("BLANKAS_MAX_ENVELOPE_BYTES", str(64 * 1024))),
        )


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def load_or_create_key(path: str) -> Ed25519PrivateKey:
    """Išdavėjo raktas sukuriamas pirmą kartą paleidus. Jį saugokite ir pasidarykite atsarginę kopiją."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit("Išdavėjo raktas turi būti Ed25519")
        return key
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


class Service:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.key = load_or_create_key(cfg.key_path)
        self.issuer = core.public_b64(self.key)
        with self.db() as conn:
            conn.executescript(SCHEMA)
            conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('issued', 0)")

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.cfg.db_path, timeout=10)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def purge(self) -> None:
        now = int(time.time())
        with self.db() as conn:
            conn.execute("DELETE FROM marks WHERE expires_at <= ?", (now,))
            conn.execute("DELETE FROM envelopes WHERE expires_at <= ?", (now,))

    def _sign(self, record: dict) -> dict:
        record["sig"] = core.sign_bytes(self.key, core.canonical(record))
        return record

    # ------------------------------------------------------------ informacija

    def used(self) -> int:
        with self.db() as conn:
            return conn.execute("SELECT value FROM meta WHERE key = 'issued'").fetchone()[0]

    def info(self):
        used = self.used()
        return 200, {
            "service": "Blankas",
            "description": ("Numbered, signed blank forms for agent-to-agent deals. Both agents fill the same "
                            "fields and sign the same hash; each keeps an identical copy. The issuer never sees "
                            "the deal. Optional: a mark (hash only) and a sealed encrypted envelope."),
            "aprasymas": ("Numeruoti, pasirašyti blankai agentų sandoriams. Abu agentai užpildo tuos pačius "
                          "laukus ir pasirašo tą patį hash; kiekvienas turi identišką egzempliorių."),
            "form": core.FORM_ID,
            "issuer": self.issuer,
            "free_quota": {"total": self.cfg.free_quota, "used": used,
                           "remaining": max(0, self.cfg.free_quota - used)},
            "envelope": {"ttl_seconds": self.cfg.ttl_seconds, "max_bytes": self.cfg.max_envelope_bytes},
            "endpoints": {
                "POST /": "RPC: {\"action\": \"issue|verify|mark|marks|deposit|retrieve|delete|info|issuer\", ...}",
                "POST /blanks": "issue a blank for two parties",
                "POST /verify": "verify a filled and signed blank (free)",
                "POST /marks": "register a mark: blank id + deal hash + time",
                "GET /marks/{blank_id}": "list active marks",
                "POST /envelopes": "deposit an encrypted envelope (sealed third copy)",
                "GET /envelopes/{id}": "retrieve an envelope (Authorization: Bearer <token>)",
                "DELETE /envelopes/{id}": "delete an envelope early",
                "GET /llms.txt": "instructions for agents",
            },
        }

    def llms_txt(self) -> str:
        hours = self.cfg.ttl_seconds / 3600
        return f"""# Blankas – standard deal forms for AI agents

Blankas issues numbered, signed blank forms ("blanks") for agent-to-agent deals.
Both agents fill the same fields and sign the same hash; each keeps an identical copy.
The issuer never sees the deal content. Pilot: the first {self.cfg.free_quota} blanks are free.

## Flow
1. POST /blanks {{"party_a": {{"sign": <Ed25519 public key>, "box": <X25519 public key>}}, "party_b": {{...}}}}
   Keys are 32 raw bytes, base64url without padding. Response: {{"blank": {{...}}}}.
2. Fill "content" (form {core.FORM_ID}):
   version (int >= 1), subject, payment, deadline, sanction (required strings),
   price {{"amount_minor": int, "currency": str}}, salt (>= 16 random bytes, base64url),
   optional strings: check, arbiter, notes. Floats are not allowed anywhere.
3. deal_hash = hex(sha256(canonical_json({{"blank": blank, "content": content}})))
   canonical_json: keys sorted, no whitespace, UTF-8, no floats (JCS-compatible for these types).
4. Each party signs the 32 raw bytes of deal_hash with its Ed25519 key (signature base64url).
5. Document = {{"blank", "content", "deal_hash", "signatures": {{"a", "b"}}}}. Both keep identical copies.
6. POST /verify {{"document": ...}} -> {{"valid": true|false, "errors": [...]}}. Free.
Rule: if several versions are co-signed on one blank, the highest "version" wins.
The agreed sanction is part of the content; Blankas does not hold or move money.

## Optional
- Mark: POST /marks {{"blank", "deal_hash", "signatures"}} -> signed receipt. The issuer sees only the hash.
  GET /marks/{{blank_id}} lists active marks.
- Envelope (sealed third copy, kept {hours:g} h, max {self.cfg.max_envelope_bytes} bytes):
  encrypt the document to both parties' X25519 keys (X25519 + HKDF-SHA256 + ChaCha20-Poly1305,
  reference: blankas_core.seal_envelope), then POST /envelopes {{"blank", "deal_hash", "signatures", "envelope"}}
  -> {{"ticket", "token"}}. GET /envelopes/{{id}} with "Authorization: Bearer <token>"; DELETE removes it early.

## RPC form (same as the n8n deployment)
POST / with {{"action": "issue" | "verify" | "mark" | "marks" | "deposit" | "retrieve" | "delete" | "info" | "issuer", ...}}
and the same fields as above (blank_id, envelope_id and token go in the body).

Issuer public key (Ed25519, base64url): {self.issuer}
Errors: JSON {{"error": code, "message": text}}. 402 = free quota exhausted (x402 payments planned).
"""

    # ------------------------------------------------------------ RPC (tas pats API kaip n8n versijoje)

    def rpc(self, body: dict, token: str | None = None):
        action = body.get("action")
        if action == "info":
            return self.info()
        if action == "issuer":
            return 200, {"issuer": self.issuer}
        if action == "issue":
            return self.issue(body)
        if action == "verify":
            return self.verify(body)
        if action == "mark":
            return self.mark(body)
        if action == "marks":
            return self.list_marks(str(body.get("blank_id", "")))
        if action == "deposit":
            return self.deposit(body)
        if action in ("retrieve", "delete"):
            return self.envelope(str(body.get("envelope_id", "")), body.get("token") or token,
                                 delete=(action == "delete"))
        raise ApiError(400, "unknown_action",
                       "Nežinomas veiksmas. Galimi: info, issuer, issue, verify, mark, marks, deposit, retrieve, delete")

    # ------------------------------------------------------------ blankai

    def issue(self, body: dict):
        party_a, party_b = core.normalize_parties(body.get("party_a"), body.get("party_b"))
        with self.db() as conn:
            cur = conn.execute("UPDATE meta SET value = value + 1 WHERE key = 'issued' AND value < ?",
                               (self.cfg.free_quota,))
            if cur.rowcount == 0:
                raise ApiError(402, "quota_exhausted",
                               f"Nemokama {self.cfg.free_quota} blankų kvota išnaudota. "
                               "Mokėjimai (x402) bus įjungti vėliau.")
            serial = conn.execute("SELECT value FROM meta WHERE key = 'issued'").fetchone()[0]
        blank = core.issue_blank(self.key, serial, party_a, party_b)
        return 201, {"blank": blank, "free_remaining": max(0, self.cfg.free_quota - serial)}

    def verify(self, body: dict):
        document = body.get("document", body)
        return 200, core.verify_document(document, trusted_issuer=self.issuer)

    def _signed_by_both(self, body: dict):
        blank, dhash, signatures = body.get("blank"), body.get("deal_hash"), body.get("signatures")
        errors = core.check_blank(blank, trusted_issuer=self.issuer)
        if not errors:
            errors = core.check_signatures(blank, dhash, signatures)
        if errors:
            raise ApiError(400, "invalid", "; ".join(errors))
        return blank, dhash

    # ------------------------------------------------------------ žymos

    def mark(self, body: dict):
        blank, dhash = self._signed_by_both(body)
        now = int(time.time())
        expires = now + self.cfg.ttl_seconds
        receipt = self._sign({"type": "zyma", "blank_id": blank["id"], "deal_hash": dhash,
                              "marked_at": core.iso(now), "expires_at": core.iso(expires),
                              "issuer": self.issuer})
        with self.db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM marks WHERE blank_id = ?", (blank["id"],)).fetchone()[0]
            if count >= self.cfg.max_marks_per_blank:
                raise ApiError(409, "limit", "Šiam blankui pasiektas žymų limitas")
            conn.execute("INSERT INTO marks(blank_id, deal_hash, receipt, expires_at) VALUES (?, ?, ?, ?)",
                         (blank["id"], dhash, json.dumps(receipt, ensure_ascii=False), expires))
        return 201, {"mark": receipt}

    def list_marks(self, blank_id: str):
        with self.db() as conn:
            rows = conn.execute("SELECT receipt FROM marks WHERE blank_id = ? ORDER BY id", (blank_id,)).fetchall()
        return 200, {"blank_id": blank_id, "marks": [json.loads(row[0]) for row in rows]}

    # ------------------------------------------------------------ vokai

    def deposit(self, body: dict):
        blank, dhash = self._signed_by_both(body)
        envelope = body.get("envelope")
        if not isinstance(envelope, dict):
            raise ApiError(400, "invalid", "'envelope' turi būti JSON objektas")
        missing = [k for k in ("v", "alg", "blank_id", "nonce", "ciphertext", "recipients") if k not in envelope]
        if missing:
            raise ApiError(400, "invalid", f"voke trūksta laukų: {', '.join(missing)}")
        if envelope["blank_id"] != blank["id"]:
            raise ApiError(400, "invalid", "voko blank_id nesutampa su blanku")
        raw = core.canonical(envelope)
        if len(raw) > self.cfg.max_envelope_bytes:
            raise ApiError(413, "too_large", f"Vokas per didelis: daugiausia {self.cfg.max_envelope_bytes} baitų")
        now = int(time.time())
        expires = now + self.cfg.ttl_seconds
        envelope_id, token = secrets.token_hex(12), secrets.token_urlsafe(24)
        ticket = self._sign({"type": "vokas", "envelope_id": envelope_id, "blank_id": blank["id"],
                             "deal_hash": dhash, "envelope_sha256": core.sha256_hex(raw),
                             "deposited_at": core.iso(now), "expires_at": core.iso(expires),
                             "issuer": self.issuer})
        with self.db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM envelopes WHERE blank_id = ?", (blank["id"],)).fetchone()[0]
            if count >= self.cfg.max_envelopes_per_blank:
                raise ApiError(409, "limit", "Šiam blankui pasiektas vokų limitas")
            conn.execute(
                "INSERT INTO envelopes(id, blank_id, token_hash, body, ticket, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (envelope_id, blank["id"], core.sha256_hex(token.encode()), raw.decode("utf-8"),
                 json.dumps(ticket, ensure_ascii=False), expires))
        return 201, {"ticket": ticket, "token": token,
                     "note": "Talonas ir žetonas reikalingi vokui atsiimti – perduokite juos ir kitai šaliai."}

    def envelope(self, envelope_id: str, token: str | None, delete: bool = False):
        if not token:
            raise ApiError(401, "token_required", "Reikalingas žetonas: Authorization: Bearer <žetonas>")
        with self.db() as conn:
            row = conn.execute("SELECT token_hash, body, ticket FROM envelopes WHERE id = ?",
                               (envelope_id,)).fetchone()
            if not row:
                raise ApiError(404, "not_found", "Vokas nerastas: jo nėra, jis ištrintas arba baigėsi terminas")
            if not secrets.compare_digest(row[0], core.sha256_hex(token.encode())):
                raise ApiError(403, "forbidden", "Neteisingas žetonas")
            if delete:
                conn.execute("DELETE FROM envelopes WHERE id = ?", (envelope_id,))
                return 200, {"deleted": envelope_id}
        return 200, {"envelope": json.loads(row[1]), "ticket": json.loads(row[2])}


class Handler(BaseHTTPRequestHandler):
    server_version = "Blankas/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # be užklausų turinio
        sys.stderr.write(f"{self.log_date_time_string()} {fmt % args}\n")

    def _send(self, status: int, payload, content_type: str = "application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else \
            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(413, "too_large", "Užklausa per didelė")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ApiError(400, "bad_json", "Netinkamas JSON") from None
        if not isinstance(data, dict):
            raise ApiError(400, "bad_json", "Tikėtasi JSON objekto")
        return data

    def _token(self, url) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return (parse_qs(url.query).get("token") or [None])[0]

    def _dispatch(self, method: str) -> None:
        service: Service = self.server.service
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        try:
            service.purge()
            if method == "GET" and parts == []:
                status, payload = service.info()
            elif method == "POST" and parts == []:
                status, payload = service.rpc(self._body(), self._token(url))
            elif method == "GET" and parts == ["llms.txt"]:
                return self._send(200, service.llms_txt().encode("utf-8"), "text/plain; charset=utf-8")
            elif method == "GET" and parts == ["issuer"]:
                status, payload = 200, {"issuer": service.issuer}
            elif method == "POST" and parts == ["blanks"]:
                status, payload = service.issue(self._body())
            elif method == "POST" and parts == ["verify"]:
                status, payload = service.verify(self._body())
            elif method == "POST" and parts == ["marks"]:
                status, payload = service.mark(self._body())
            elif method == "GET" and len(parts) == 2 and parts[0] == "marks":
                status, payload = service.list_marks(parts[1])
            elif method == "POST" and parts == ["envelopes"]:
                status, payload = service.deposit(self._body())
            elif method in ("GET", "DELETE") and len(parts) == 2 and parts[0] == "envelopes":
                status, payload = service.envelope(parts[1], self._token(url), delete=(method == "DELETE"))
            else:
                raise ApiError(404, "not_found", "Tokio adreso nėra. Žr. GET /")
        except ApiError as exc:
            status, payload = exc.status, {"error": exc.code, "message": exc.message}
        except ValueError as exc:
            status, payload = 400, {"error": "invalid", "message": str(exc)}
        except Exception as exc:  # vidaus klaidų detalės klientui neatskleidžiamos
            self.log_error("Vidinė klaida: %r", exc)
            status, payload = 500, {"error": "internal", "message": "Vidinė serverio klaida"}
        self._send(status, payload)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_OPTIONS(self):
        self._send(204, b"")


def make_server(cfg: Config) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), Handler)
    httpd.daemon_threads = True
    httpd.service = Service(cfg)
    return httpd


def main() -> None:
    cfg = Config.from_env()
    httpd = make_server(cfg)
    host, port = httpd.server_address[:2]
    print(f"Blankas veikia: http://{host}:{port}")
    print(f"Išdavėjo viešasis raktas: {httpd.service.issuer}")
    print(f"Nemokama kvota: {cfg.free_quota} blankų (išduota: {httpd.service.used()}); "
          f"voko terminas: {cfg.ttl_seconds / 3600:g} val.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nSustabdyta.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
