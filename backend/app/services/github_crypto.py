"""Pure-Python RSA private key parser and RS256 JWT signer for GitHub App auth.

Implements ASN.1 DER parsing for PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8
(`BEGIN PRIVATE KEY`) RSA keys and RFC 8017 RSASSA-PKCS1-v1_5 with SHA-256 (`RS256`)
without requiring external native cryptography packages.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

# RFC 8017 Appendix B.1 DigestInfo prefix for SHA-256
_SHA256_DIGEST_INFO_PREFIX: bytes = bytes.fromhex("3031300d060960864801650304020105000420")

# OID 1.2.840.113549.1.1.1 (rsaEncryption) DER value bytes
_RSA_ENCRYPTION_OID_BYTES: bytes = bytes.fromhex("2a864886f70d010101")

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OBJECT_IDENTIFIER = 0x06
_TAG_SEQUENCE = 0x30

MIN_RSA_KEY_BITS: int = 2048


class GitHubKeyError(ValueError):
    """Raised when a GitHub App private key is invalid, unsupported, or corrupt."""


@dataclass(frozen=True, slots=True)
class RSAPrivateKey:
    """Validated RSA private key parameters extracted from PEM/DER."""

    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    def __repr__(self) -> str:
        return f"RSAPrivateKey(bits={self.bit_length})"

    __str__ = __repr__


def _base64url_encode(data: bytes) -> str:
    """Return unpadded RFC 7515 base64url string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(segment: str) -> bytes:
    """Decode unpadded RFC 7515 base64url string."""
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _parse_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Parse one strict ASN.1 DER Tag-Length-Value tuple."""
    if offset >= len(data):
        raise GitHubKeyError("Unexpected end of DER private key structure")

    tag = data[offset]
    if (tag & 0x1F) == 0x1F:
        raise GitHubKeyError("Unsupported high-tag-number ASN.1 element")
    pos = offset + 1

    if pos >= len(data):
        raise GitHubKeyError("Truncated DER length field")

    length_byte = data[pos]
    pos += 1

    if length_byte == 0x80:
        raise GitHubKeyError("Indefinite-length DER encoding is not allowed")

    if length_byte < 0x80:
        length = length_byte
    else:
        num_len_bytes = length_byte & 0x7F
        if num_len_bytes > 4 or pos + num_len_bytes > len(data):
            raise GitHubKeyError("Invalid DER multi-byte length")
        len_slice = data[pos : pos + num_len_bytes]
        if len_slice[0] == 0:
            raise GitHubKeyError("Non-minimal DER length encoding")
        length = int.from_bytes(len_slice, "big")
        if length < 0x80:
            raise GitHubKeyError("Non-canonical DER long-form length")
        pos += num_len_bytes

    value_end = pos + length
    if value_end > len(data):
        raise GitHubKeyError("Truncated DER element value")

    return tag, data[pos:value_end], value_end


def _parse_sequence_children(seq_bytes: bytes) -> list[tuple[int, bytes]]:
    """Parse all direct child TLV items of a DER SEQUENCE body."""
    items: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(seq_bytes):
        tag, val, pos = _parse_tlv(seq_bytes, pos)
        items.append((tag, val))
    return items


def _decode_non_negative_integer(val_bytes: bytes) -> int:
    """Decode a strict DER non-negative INTEGER."""
    if not val_bytes:
        raise GitHubKeyError("Empty DER integer")
    if (val_bytes[0] & 0x80) != 0:
        raise GitHubKeyError("Negative integer in RSA key")
    if len(val_bytes) > 1 and val_bytes[0] == 0x00 and (val_bytes[1] & 0x80) == 0:
        raise GitHubKeyError("Non-minimal DER integer encoding")
    return int.from_bytes(val_bytes, "big")


def _parse_pkcs1_der(der_bytes: bytes) -> RSAPrivateKey:
    """Parse PKCS#1 RSAPrivateKey DER bytes."""
    tag, seq_body, end_pos = _parse_tlv(der_bytes, 0)
    if tag != _TAG_SEQUENCE or end_pos != len(der_bytes):
        raise GitHubKeyError("Invalid PKCS#1 RSA private key top-level sequence")

    children = _parse_sequence_children(seq_body)
    if len(children) != 9:
        raise GitHubKeyError("PKCS#1 RSA private key has invalid required field count")

    ints: list[int] = []
    for child_tag, child_val in children:
        if child_tag != _TAG_INTEGER:
            raise GitHubKeyError("Unexpected non-integer field in PKCS#1 RSA private key")
        ints.append(_decode_non_negative_integer(child_val))

    version, n, e, d, p, q, dp, dq, qinv = ints
    if version != 0:
        raise GitHubKeyError("Multi-prime RSA private keys (version != 0) are not supported")

    return RSAPrivateKey(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)


def _parse_pkcs8_der(der_bytes: bytes) -> RSAPrivateKey:
    """Parse PKCS#8 PrivateKeyInfo DER bytes wrapping an RSA key."""
    tag, seq_body, end_pos = _parse_tlv(der_bytes, 0)
    if tag != _TAG_SEQUENCE or end_pos != len(der_bytes):
        raise GitHubKeyError("Invalid PKCS#8 PrivateKeyInfo structure")

    children = _parse_sequence_children(seq_body)
    if len(children) < 3 or len(children) > 4:
        raise GitHubKeyError("PKCS#8 PrivateKeyInfo has invalid field count")
    if len(children) == 4 and children[3][0] != 0xA0:
        raise GitHubKeyError("Unexpected trailing element in PKCS#8 PrivateKeyInfo")

    ver_tag, ver_val = children[0]
    if ver_tag != _TAG_INTEGER or _decode_non_negative_integer(ver_val) != 0:
        raise GitHubKeyError("Unsupported PKCS#8 PrivateKeyInfo version")

    alg_tag, alg_val = children[1]
    if alg_tag != _TAG_SEQUENCE:
        raise GitHubKeyError("Invalid PKCS#8 AlgorithmIdentifier")
    alg_children = _parse_sequence_children(alg_val)
    if not alg_children or len(alg_children) > 2 or alg_children[0][0] != _TAG_OBJECT_IDENTIFIER:
        raise GitHubKeyError("Missing algorithm OID in PKCS#8 PrivateKeyInfo")
    if alg_children[0][1] != _RSA_ENCRYPTION_OID_BYTES:
        raise GitHubKeyError("Private key algorithm is not RSA (rsaEncryption)")
    if len(alg_children) == 2 and (alg_children[1][0] != _TAG_NULL or alg_children[1][1] != b""):
        raise GitHubKeyError("Invalid RSA AlgorithmIdentifier parameters in PKCS#8 key")

    key_tag, key_octet_bytes = children[2]
    if key_tag != _TAG_OCTET_STRING:
        raise GitHubKeyError("PKCS#8 privateKey field must be an OCTET STRING")

    return _parse_pkcs1_der(key_octet_bytes)


def _extract_pem_der(pem_text: str) -> tuple[str, bytes]:
    """Extract kind ('pkcs1' or 'pkcs8') and DER bytes from PEM text."""
    cleaned = pem_text.replace("\\n", "\n").strip()
    if not cleaned:
        raise GitHubKeyError("Private key PEM is empty")

    if "ENCRYPTED" in cleaned.upper() and (
        "BEGIN ENCRYPTED PRIVATE KEY" in cleaned or "PROC-TYPE: 4,ENCRYPTED" in cleaned.upper()
    ):
        raise GitHubKeyError("Passphrase-encrypted private keys are not supported")

    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    if len(lines) < 3:
        raise GitHubKeyError("Private key PEM structure is incomplete")

    header = lines[0]
    footer = lines[-1]

    if header == "-----BEGIN RSA PRIVATE KEY-----" and footer == "-----END RSA PRIVATE KEY-----":
        kind = "pkcs1"
    elif header == "-----BEGIN PRIVATE KEY-----" and footer == "-----END PRIVATE KEY-----":
        kind = "pkcs8"
    else:
        raise GitHubKeyError("Unsupported or malformed PEM private key headers")

    b64_body = "".join(lines[1:-1])
    if "-----" in b64_body:
        raise GitHubKeyError("Multiple PEM blocks or malformed PEM body detected")

    try:
        der_bytes = base64.b64decode(b64_body.encode("ascii"), validate=True)
    except Exception as exc:
        raise GitHubKeyError("Invalid base64 encoding in PEM private key") from exc

    return kind, der_bytes


def parse_rsa_private_key_pem(
    pem_text: str,
    *,
    min_key_bits: int = MIN_RSA_KEY_BITS,
) -> RSAPrivateKey:
    """Parse and cryptographically sanity-check an RSA private key from PEM."""
    kind, der_bytes = _extract_pem_der(pem_text)
    key = _parse_pkcs1_der(der_bytes) if kind == "pkcs1" else _parse_pkcs8_der(der_bytes)

    if key.bit_length < min_key_bits:
        raise GitHubKeyError(
            f"RSA private key modulus ({key.bit_length} bits) is below minimum required {min_key_bits} bits"
        )
    if key.e < 3 or (key.e % 2) == 0:
        raise GitHubKeyError("RSA public exponent must be an odd integer >= 3")
    if key.d <= 1 or key.d >= key.n:
        raise GitHubKeyError("Invalid RSA private exponent range")
    if key.p <= 1 or key.q <= 1 or key.p == key.q or key.p * key.q != key.n:
        raise GitHubKeyError("RSA prime factors do not match modulus")
    if key.dp != key.d % (key.p - 1) or key.dq != key.d % (key.q - 1):
        raise GitHubKeyError("RSA CRT exponents failed consistency check")
    if (key.q * key.qinv) % key.p != 1:
        raise GitHubKeyError("RSA CRT coefficient failed consistency check")
    if pow(pow(0x12345678, key.e, key.n), key.d, key.n) != 0x12345678:
        raise GitHubKeyError("RSA key exponents failed consistency check")

    return key


def sign_rs256(key: RSAPrivateKey, message: bytes) -> bytes:
    """Sign `message` using RFC 8017 RSASSA-PKCS1-v1_5 with SHA-256."""
    em_len = (key.n.bit_length() + 7) // 8
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGEST_INFO_PREFIX + digest
    if em_len < len(t) + 11:
        raise GitHubKeyError("Intended encoded message length is too short for RSA modulus")

    ps = b"\xff" * (em_len - len(t) - 3)
    em = b"\x00\x01" + ps + b"\x00" + t
    m = int.from_bytes(em, "big")

    # Chinese Remainder Theorem modular exponentiation
    s1 = pow(m % key.p, key.dp, key.p)
    s2 = pow(m % key.q, key.dq, key.q)
    h = (key.qinv * (s1 - s2)) % key.p
    s = s2 + h * key.q

    return s.to_bytes(em_len, "big")


def verify_rs256(n: int, e: int, message: bytes, signature: bytes) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 SHA-256 signature against public key `(n, e)`."""
    em_len = (n.bit_length() + 7) // 8
    if len(signature) != em_len:
        return False
    s = int.from_bytes(signature, "big")
    if s < 0 or s >= n:
        return False

    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGEST_INFO_PREFIX + digest
    if em_len < len(t) + 11:
        return False

    ps = b"\xff" * (em_len - len(t) - 3)
    expected_em = b"\x00\x01" + ps + b"\x00" + t

    m = pow(s, e, n)
    actual_em = m.to_bytes(em_len, "big")
    return hmac.compare_digest(actual_em, expected_em)


def create_github_app_jwt(
    app_id: int,
    private_key: RSAPrivateKey,
    *,
    now: int | None = None,
    ttl_seconds: int = 540,
) -> str:
    """Create a short-lived signed RS256 JWT for GitHub App authentication."""
    if isinstance(app_id, bool) or not isinstance(app_id, int) or app_id <= 0:
        raise ValueError("GitHub App ID must be a positive integer")
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or ttl_seconds <= 0
        or ttl_seconds > 540
    ):
        raise ValueError(
            "GitHub App JWT ttl_seconds must be between 1 and 540 (so exp - iat <= 600s)"
        )

    current_ts = int(time.time()) if now is None else int(now)
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iat": current_ts - 60,
        "exp": current_ts + ttl_seconds,
        "iss": str(app_id),
    }

    encoded_header = _base64url_encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _base64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = sign_rs256(private_key, signing_input)
    encoded_sig = _base64url_encode(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_sig}"
