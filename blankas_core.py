"""Blankas – bendra logika serveriui ir agentams.

Kanoninis JSON, Ed25519 parašai, blanko forma „agent-deal-v1“ ir užšifruoti vokai.
Vienintelė priklausomybė – biblioteka `cryptography`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORM_ID = "agent-deal-v1"
ENVELOPE_ALG = "X25519-HKDF-SHA256+ChaCha20Poly1305"
MAX_TEXT = 2000
REQUIRED_TEXT = ("subject", "payment", "deadline", "sanction")
OPTIONAL_TEXT = ("check", "arbiter", "notes")

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw


# ---------------------------------------------------------------- pagalbinės

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("tikėtasi base64url eilutės")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def iso(epoch: float | None = None) -> str:
    moment = datetime.now(timezone.utc) if epoch is None else datetime.fromtimestamp(epoch, timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _no_floats(obj, path: str = "$") -> None:
    if isinstance(obj, float):
        raise ValueError(f"{path}: trupmeniniai skaičiai neleidžiami – naudokite sveikuosius (pvz., centus)")
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: raktai turi būti eilutės")
            _no_floats(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            _no_floats(value, f"{path}[{i}]")


def canonical(obj) -> bytes:
    """Kanoninis JSON: surikiuoti raktai, be tarpų, UTF-8, be trupmenų (šiems tipams suderinama su JCS)."""
    _no_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_bytes(key: Ed25519PrivateKey, data: bytes) -> str:
    return b64e(key.sign(data))


def verify_sig(public_b64: str, data: bytes, sig_b64: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64d(public_b64)).verify(b64d(sig_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_b64(key) -> str:
    return b64e(key.public_key().public_bytes(_RAW, _RAW_PUB))


# ---------------------------------------------------------------- agento tapatybė

@dataclass
class Identity:
    """Agento raktai: `sign` (Ed25519) parašams, `box` (X25519) vokams atidaryti."""

    sign_key: Ed25519PrivateKey
    box_key: X25519PrivateKey

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    def public(self) -> dict:
        return {"sign": public_b64(self.sign_key), "box": public_b64(self.box_key)}

    def to_dict(self) -> dict:
        """SLAPTA: privatūs raktai. Laikyti tik pas patį agentą."""
        private = serialization.PrivateFormat.Raw
        none = serialization.NoEncryption()
        return {
            "sign_private": b64e(self.sign_key.private_bytes(_RAW, private, none)),
            "box_private": b64e(self.box_key.private_bytes(_RAW, private, none)),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Identity":
        return cls(
            Ed25519PrivateKey.from_private_bytes(b64d(data["sign_private"])),
            X25519PrivateKey.from_private_bytes(b64d(data["box_private"])),
        )

    def save(self, path: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f)

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


# ---------------------------------------------------------------- blankas

def _normalize_party(party, role: str) -> dict:
    if not isinstance(party, dict):
        raise ValueError(f"šalis {role}: tikėtasi objekto su raktais 'sign' ir 'box'")
    out = {}
    for name in ("sign", "box"):
        value = party.get(name)
        try:
            raw = b64d(value) if isinstance(value, str) else b""
        except ValueError:
            raw = b""
        if len(raw) != 32:
            raise ValueError(f"šalis {role}: '{name}' turi būti 32 baitų viešasis raktas (base64url)")
        out[name] = b64e(raw)
    return out


def normalize_parties(party_a, party_b) -> tuple[dict, dict]:
    a = _normalize_party(party_a, "a")
    b = _normalize_party(party_b, "b")
    if a["sign"] == b["sign"] or a["box"] == b["box"]:
        raise ValueError("šalys a ir b turi turėti skirtingus raktus")
    return a, b


def _without_sig(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k != "sig"}


def issue_blank(issuer_key: Ed25519PrivateKey, serial: int, party_a: dict, party_b: dict) -> dict:
    """Išduoda pasirašytą blanką. Šalių raktai turi būti jau patikrinti (normalize_parties)."""
    blank = {
        "type": "blankas",
        "form": FORM_ID,
        "serial": serial,
        "id": f"BLK-{serial:06d}-{os.urandom(3).hex()}",
        "issued_at": iso(),
        "parties": {"a": party_a, "b": party_b},
        "issuer": public_b64(issuer_key),
    }
    blank["sig"] = sign_bytes(issuer_key, canonical(blank))
    return blank


def check_blank(blank, trusted_issuer: str | None = None) -> list[str]:
    if not isinstance(blank, dict):
        return ["blankas turi būti JSON objektas"]
    missing = [k for k in ("type", "form", "serial", "id", "issued_at", "parties", "issuer", "sig") if k not in blank]
    if missing:
        return [f"blanke trūksta laukų: {', '.join(missing)}"]
    errors = []
    if blank["type"] != "blankas" or blank["form"] != FORM_ID:
        errors.append("nežinomas blanko tipas arba forma")
    try:
        parties = blank["parties"]
        normalize_parties(parties.get("a"), parties.get("b"))
    except (ValueError, AttributeError) as exc:
        errors.append(str(exc))
    if trusted_issuer and blank["issuer"] != trusted_issuer:
        errors.append("blanką išdavė ne patikimas išdavėjas")
    try:
        body = canonical(_without_sig(blank))
    except ValueError as exc:
        return errors + [str(exc)]
    if not verify_sig(blank["issuer"], body, blank["sig"]):
        errors.append("išdavėjo parašas negalioja – blankas suklastotas arba pakeistas")
    return errors


# ---------------------------------------------------------------- turinys (forma agent-deal-v1)

def fill(blank: dict, *, subject: str, price_minor: int, currency: str, payment: str, deadline: str,
         sanction: str, version: int = 1, check: str | None = None, arbiter: str | None = None,
         notes: str | None = None) -> dict:
    """Užpildo blanko laukus. Druska pridedama automatiškai, kad hash nebūtų galima atspėti."""
    content = {
        "version": version,
        "subject": subject,
        "price": {"amount_minor": price_minor, "currency": currency},
        "payment": payment,
        "deadline": deadline,
        "sanction": sanction,
        "salt": b64e(os.urandom(16)),
    }
    for name, value in (("check", check), ("arbiter", arbiter), ("notes", notes)):
        if value is not None:
            content[name] = value
    errors = check_content(content)
    if errors:
        raise ValueError("; ".join(errors))
    return content


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def check_content(content) -> list[str]:
    if not isinstance(content, dict):
        return ["turinys turi būti JSON objektas"]
    errors = []
    allowed = {"version", "subject", "price", "payment", "deadline", "sanction", "salt", *OPTIONAL_TEXT}
    errors += [f"nežinomas laukas '{k}'" for k in content if k not in allowed]
    if not (_is_int(content.get("version")) and content["version"] >= 1):
        errors.append("'version' turi būti sveikasis skaičius ≥ 1")
    for name in REQUIRED_TEXT:
        value = content.get(name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"privalomas tekstinis laukas '{name}'")
        elif len(value) > MAX_TEXT:
            errors.append(f"laukas '{name}' per ilgas (daugiausia {MAX_TEXT} simbolių)")
    for name in OPTIONAL_TEXT:
        if name in content and (not isinstance(content[name], str) or len(content[name]) > MAX_TEXT):
            errors.append(f"laukas '{name}' turi būti tekstas iki {MAX_TEXT} simbolių")
    price = content.get("price")
    if not isinstance(price, dict):
        errors.append("'price' turi būti objektas {amount_minor, currency}")
    else:
        if set(price) - {"amount_minor", "currency"}:
            errors.append("'price' leidžiami tik laukai amount_minor ir currency")
        if not (_is_int(price.get("amount_minor")) and price["amount_minor"] >= 0):
            errors.append("'price.amount_minor' – sveikasis skaičius ≥ 0 mažiausiais vienetais (pvz., centais)")
        currency = price.get("currency")
        if not (isinstance(currency, str) and 2 <= len(currency) <= 10):
            errors.append("'price.currency' – valiutos kodas, pvz., EUR ar USDC")
    try:
        if len(b64d(content.get("salt"))) < 16:
            errors.append("'salt' – bent 16 atsitiktinių baitų (base64url)")
    except ValueError:
        errors.append("'salt' – privaloma base64url eilutė")
    try:
        canonical(content)
    except ValueError as exc:
        errors.append(str(exc))
    return errors


# ---------------------------------------------------------------- sandorio hash, parašai, dokumentas

def deal_hash(blank: dict, content: dict) -> str:
    """Abiejų šalių pasirašomas hash: sha256(kanoninis {blank, content})."""
    return sha256_hex(canonical({"blank": blank, "content": content}))


def sign_deal(identity: Identity, dhash: str) -> str:
    return sign_bytes(identity.sign_key, bytes.fromhex(dhash))


def assemble(blank: dict, content: dict, sig_a: str, sig_b: str) -> dict:
    """Užpildytas blankas. Abu agentai laiko po identišką egzempliorių."""
    return {"blank": blank, "content": content, "deal_hash": deal_hash(blank, content),
            "signatures": {"a": sig_a, "b": sig_b}}


def check_signatures(blank: dict, dhash, signatures) -> list[str]:
    try:
        digest = bytes.fromhex(dhash)
        if len(digest) != 32:
            raise ValueError
    except (ValueError, TypeError):
        return ["'deal_hash' turi būti 64 simbolių hex eilutė"]
    if not isinstance(signatures, dict):
        return ["'signatures' turi būti objektas {a, b}"]
    errors = []
    for role in ("a", "b"):
        sig = signatures.get(role)
        if not isinstance(sig, str) or not verify_sig(blank["parties"][role]["sign"], digest, sig):
            errors.append(f"šalies {role} parašas negalioja arba jo nėra")
    return errors


def verify_document(doc, trusted_issuer: str | None = None) -> dict:
    """Patikrina užpildytą blanką be serverio: išdavėjo parašą, formą, hash ir abu parašus."""
    if not isinstance(doc, dict):
        return {"valid": False, "errors": ["dokumentas turi būti JSON objektas"]}
    blank, content = doc.get("blank"), doc.get("content")
    errors = check_blank(blank, trusted_issuer) + check_content(content)
    if not errors:
        dhash = deal_hash(blank, content)
        if doc.get("deal_hash") != dhash:
            errors.append("deal_hash nesutampa su turiniu – dokumentas pakeistas")
        errors += check_signatures(blank, dhash, doc.get("signatures"))
    return {
        "valid": not errors,
        "errors": errors,
        "blank_id": blank.get("id") if isinstance(blank, dict) else None,
        "version": content.get("version") if isinstance(content, dict) else None,
    }


def check_receipt(receipt, trusted_issuer: str | None = None) -> list[str]:
    """Patikrina žymos kvitą arba voko taloną."""
    if not isinstance(receipt, dict) or "sig" not in receipt or "issuer" not in receipt:
        return ["netinkamas kvitas ar talonas"]
    errors = []
    if trusted_issuer and receipt["issuer"] != trusted_issuer:
        errors.append("išdavė ne patikimas išdavėjas")
    if not verify_sig(receipt["issuer"], canonical(_without_sig(receipt)), receipt["sig"]):
        errors.append("išdavėjo parašas negalioja")
    return errors


# ---------------------------------------------------------------- vokas (trečia užšifruota kopija)

def _kek(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"blankas-envelope-v1" + eph_pub + recipient_pub).derive(shared)


def seal_envelope(doc: dict) -> dict:
    """Užšifruoja užpildytą blanką abiejų šalių `box` raktais. Saugykla turinio neperskaitys."""
    blank = doc["blank"]
    aad = blank["id"].encode("utf-8")
    content_key, nonce = os.urandom(32), os.urandom(12)
    recipients = {}
    for role in ("a", "b"):
        recipient_pub = b64d(blank["parties"][role]["box"])
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(_RAW, _RAW_PUB)
        kek = _kek(eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub)), eph_pub, recipient_pub)
        wrap_nonce = os.urandom(12)
        recipients[role] = {"eph": b64e(eph_pub), "nonce": b64e(wrap_nonce),
                            "key": b64e(ChaCha20Poly1305(kek).encrypt(wrap_nonce, content_key, aad))}
    return {
        "v": 1,
        "alg": ENVELOPE_ALG,
        "blank_id": blank["id"],
        "nonce": b64e(nonce),
        "ciphertext": b64e(ChaCha20Poly1305(content_key).encrypt(nonce, canonical(doc), aad)),
        "recipients": recipients,
    }


def open_envelope(envelope: dict, identity: Identity, role: str) -> dict:
    """Atidaro voką savo `box` raktu. `role` – 'a' arba 'b'."""
    aad = envelope["blank_id"].encode("utf-8")
    entry = envelope["recipients"][role]
    eph_pub = b64d(entry["eph"])
    my_pub = identity.box_key.public_key().public_bytes(_RAW, _RAW_PUB)
    kek = _kek(identity.box_key.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, my_pub)
    content_key = ChaCha20Poly1305(kek).decrypt(b64d(entry["nonce"]), b64d(entry["key"]), aad)
    plain = ChaCha20Poly1305(content_key).decrypt(b64d(envelope["nonce"]), b64d(envelope["ciphertext"]), aad)
    return json.loads(plain)
