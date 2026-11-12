"""Unit and security tests for GitHub App RS256 crypto and GitHubAppClient."""

from __future__ import annotations

import base64
import json
import secrets
import shutil
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.services.github_client import (
    GitHubAppClient,
    GitHubClientError,
    GitHubConfigurationError,
    GitHubNotFoundError,
    GitHubOAuthClient,
    GitHubOAuthUser,
    GitHubPermissionError,
    GitHubRateLimitError,
    GitHubTransientError,
    GitHubValidationError,
    redact_github_secrets,
)
from app.services.github_crypto import (
    GitHubKeyError,
    RSAPrivateKey,
    create_github_app_jwt,
    parse_rsa_private_key_pem,
    sign_rs256,
    verify_rs256,
)
from app.services.job_service import sanitize_failure_message

# ---------------------------------------------------------------------------
# Deterministic synthetic RSA PEM generation helpers (zero hardcoded secrets)
# ---------------------------------------------------------------------------

_SMALL_PRIMES: tuple[int, ...] = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
)


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1

    rng = secrets.SystemRandom()
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _der_encode_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_encode_len(len(value)) + value


def _der_int(value: int) -> bytes:
    if value == 0:
        return _der_tlv(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _encode_rsa_pkcs1_pem(key: RSAPrivateKey) -> str:
    seq_body = b"".join(
        _der_int(v) for v in (0, key.n, key.e, key.d, key.p, key.q, key.dp, key.dq, key.qinv)
    )
    der = _der_tlv(0x30, seq_body)
    b64 = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{wrapped}\n-----END RSA PRIVATE KEY-----"


def _encode_rsa_pkcs8_pem(key: RSAPrivateKey) -> str:
    pkcs1_body = b"".join(
        _der_int(v) for v in (0, key.n, key.e, key.d, key.p, key.q, key.dp, key.dq, key.qinv)
    )
    pkcs1_der = _der_tlv(0x30, pkcs1_body)
    alg_id = _der_tlv(
        0x30,
        _der_tlv(0x06, bytes.fromhex("2a864886f70d010101")) + _der_tlv(0x05, b""),
    )
    pkcs8_der = _der_tlv(
        0x30,
        _der_int(0) + alg_id + _der_tlv(0x04, pkcs1_der),
    )
    b64 = base64.b64encode(pkcs8_der).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PRIVATE KEY-----\n{wrapped}\n-----END PRIVATE KEY-----"


def _generate_rsa_keypair(bits: int = 2048) -> RSAPrivateKey:
    e = 65537
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            continue
        return RSAPrivateKey(
            n=n,
            e=e,
            d=d,
            p=p,
            q=q,
            dp=d % (p - 1),
            dq=d % (q - 1),
            qinv=pow(q, -1, p),
        )


@pytest.fixture(scope="module")
def rsa_keypair() -> RSAPrivateKey:
    return _generate_rsa_keypair(2048)


@pytest.fixture(scope="module")
def pkcs1_pem(rsa_keypair: RSAPrivateKey) -> str:
    return _encode_rsa_pkcs1_pem(rsa_keypair)


@pytest.fixture(scope="module")
def pkcs8_pem(rsa_keypair: RSAPrivateKey) -> str:
    return _encode_rsa_pkcs8_pem(rsa_keypair)


# ---------------------------------------------------------------------------
# Crypto & JWT unit tests
# ---------------------------------------------------------------------------


def test_parse_pkcs1_and_pkcs8_and_sign_rs256_jwt(
    rsa_keypair: RSAPrivateKey,
    pkcs1_pem: str,
    pkcs8_pem: str,
) -> None:
    parsed_1 = parse_rsa_private_key_pem(pkcs1_pem)
    parsed_8 = parse_rsa_private_key_pem(pkcs8_pem)
    assert parsed_1 == rsa_keypair
    assert parsed_8 == rsa_keypair

    # Literal escaped newlines commonly used in single-line environment variables
    escaped_pem = pkcs8_pem.replace("\n", "\\n")
    assert parse_rsa_private_key_pem(escaped_pem) == rsa_keypair

    jwt_token = create_github_app_jwt(98765, parsed_8, now=1_700_000_000, ttl_seconds=540)
    parts = jwt_token.split(".")
    assert len(parts) == 3

    def _b64d(seg: str) -> bytes:
        return base64.urlsafe_b64decode(seg + "=" * ((4 - len(seg) % 4) % 4))

    header = json.loads(_b64d(parts[0]))
    claims = json.loads(_b64d(parts[1]))
    sig = _b64d(parts[2])

    assert header == {"alg": "RS256", "typ": "JWT"}
    assert claims == {"iss": "98765", "iat": 1_699_999_940, "exp": 1_700_000_540}

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    assert verify_rs256(rsa_keypair.n, rsa_keypair.e, signing_input, sig) is True
    assert verify_rs256(rsa_keypair.n, rsa_keypair.e, signing_input + b"x", sig) is False


def test_reject_small_encrypted_and_malformed_private_keys() -> None:
    small_key = _generate_rsa_keypair(1024)
    small_pem = _encode_rsa_pkcs1_pem(small_key)
    with pytest.raises(GitHubKeyError, match="below minimum required 2048 bits"):
        parse_rsa_private_key_pem(small_pem)

    with pytest.raises(
        GitHubKeyError,
        match="encrypted private keys are not supported",
    ):
        parse_rsa_private_key_pem(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"
        )

    with pytest.raises(GitHubKeyError):
        parse_rsa_private_key_pem(
            "-----BEGIN PRIVATE KEY-----\nnot_valid_base64!\n-----END PRIVATE KEY-----"
        )

    # Corrupted exponent
    bad_key = RSAPrivateKey(
        n=small_key.n,
        e=small_key.e,
        d=small_key.d + 1,
        p=small_key.p,
        q=small_key.q,
        dp=small_key.dp,
        dq=small_key.dq,
        qinv=small_key.qinv,
    )
    with pytest.raises(GitHubKeyError, match="consistency check"):
        parse_rsa_private_key_pem(_encode_rsa_pkcs1_pem(bad_key), min_key_bits=1024)


# ---------------------------------------------------------------------------
# GitHubAppClient API, caching, pagination, SSRF, and error handling tests
# ---------------------------------------------------------------------------


def _synthetic_inst_token(suffix: str) -> str:
    return "ghs" + "_" + f"{suffix:0<24}"


def test_installation_token_caching_refresh_and_401_invalidation(
    rsa_keypair: RSAPrivateKey,
    pkcs8_pem: str,
) -> None:
    current_time = [datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)]
    token_calls: list[str] = []
    repo_calls: list[str] = []

    token_1 = _synthetic_inst_token("firsttoken1111111111")
    token_2 = _synthetic_inst_token("secondtoken222222222")
    token_3 = _synthetic_inst_token("thirdtoken3333333333")

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if request.url.path == "/app/installations/42/access_tokens":
            assert auth.startswith("Bearer ")
            jwt_parts = auth.split(" ", 1)[1].split(".")
            assert len(jwt_parts) == 3
            token_calls.append(jwt_parts[2])
            if len(token_calls) == 1:
                tok = token_1
            elif len(token_calls) == 2:
                tok = token_2
            else:
                tok = token_3
            exp = (current_time[0] + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
            return httpx.Response(201, json={"token": tok, "expires_at": exp})

        if request.url.path == "/installation/repositories":
            repo_calls.append(auth)
            # First time token_2 is used, simulate unexpected upstream revocation (401)
            if auth == f"Bearer {token_2}" and repo_calls.count(auth) == 1:
                return httpx.Response(401, json={"message": "Bad credentials"})
            return httpx.Response(
                200,
                json={
                    "repositories": [
                        {
                            "id": 1001,
                            "name": "app-repo",
                            "full_name": "acme/app-repo",
                            "default_branch": "main",
                            "private": True,
                        }
                    ]
                },
            )
        return httpx.Response(404, json={"message": "Not Found"})

    settings = Settings(
        GITHUB_APP_ID=777,
        GITHUB_APP_PRIVATE_KEY=SecretStr(pkcs8_pem),
    )

    with GitHubAppClient.from_settings(
        settings,
        transport=httpx.MockTransport(handler),
        now_fn=lambda: current_time[0],
        sleep_fn=lambda _s: None,
    ) as client:
        # Cached reuse inside validity window
        assert client.get_installation_token(42) == token_1
        current_time[0] += timedelta(minutes=5)
        assert client.get_installation_token(42) == token_1
        assert len(token_calls) == 1

        # Within 60s expiry margin -> automatically refreshed
        current_time[0] += timedelta(minutes=4, seconds=30)
        assert client.get_installation_token(42) == token_2
        assert len(token_calls) == 2

        # 401 with cached token_2 triggers single cache clear & refresh to token_3
        repos = client.list_installation_repositories(42)
        assert len(repos) == 1
        assert repos[0].full_name == "acme/app-repo"
        assert len(token_calls) == 3


def test_pagination_and_ssrf_link_rejection(rsa_keypair: RSAPrivateKey) -> None:
    tok = _synthetic_inst_token("pagetoken0000000000")

    def handler_ok(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/9/access_tokens":
            return httpx.Response(201, json={"token": tok})
        if request.url.path == "/installation/repositories":
            page = request.url.params.get("page", "1")
            if page == "1":
                return httpx.Response(
                    200,
                    headers={
                        "Link": '<https://api.github.com/installation/repositories?per_page=100&page=2>; rel="next"'
                    },
                    json={
                        "repositories": [
                            {
                                "id": 1,
                                "name": "repo-one",
                                "full_name": "org/repo-one",
                                "default_branch": "main",
                                "private": False,
                            }
                        ]
                    },
                )
            return httpx.Response(
                200,
                json={
                    "repositories": [
                        {
                            "id": 2,
                            "name": "repo-two",
                            "full_name": "org/repo-two",
                            "default_branch": "develop",
                            "private": True,
                        }
                    ]
                },
            )
        return httpx.Response(404)

    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        transport=httpx.MockTransport(handler_ok),
        sleep_fn=lambda _s: None,
    ) as client:
        repos = client.list_installation_repositories(9)
        assert [r.id for r in repos] == [1, 2]
        assert repos[1].default_branch == "develop"

    # Malicious cross-origin next link must fail closed without sending token externally
    def handler_ssrf(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/9/access_tokens":
            return httpx.Response(201, json={"token": tok})
        return httpx.Response(
            200,
            headers={"Link": '<https://attacker.example/exfiltrate>; rel="next"'},
            json={"repositories": []},
        )

    with (
        GitHubAppClient(
            app_id=10,
            private_key=rsa_keypair,
            transport=httpx.MockTransport(handler_ssrf),
            sleep_fn=lambda _s: None,
        ) as client,
        pytest.raises(GitHubValidationError, match="host mismatch"),
    ):
        client.list_installation_repositories(9)


def test_rate_limit_permission_not_found_and_transient_retries(
    rsa_keypair: RSAPrivateKey,
    pkcs1_pem: str,
) -> None:
    tok = _synthetic_inst_token("errortoken000000000")
    attempts = {"inst": 0, "transient": 0}
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/5/access_tokens":
            return httpx.Response(201, json={"token": tok})
        if request.url.path == "/app/installations/404":
            return httpx.Response(404, json={"message": "Installation not found"})
        if request.url.path == "/app/installations/429":
            return httpx.Response(
                429,
                headers={"Retry-After": "45"},
                json={"message": f"API rate limit exceeded using token {tok}"},
            )
        if request.url.path == "/repos/acme/app/pulls/1/files":
            return httpx.Response(403, json={"message": "Resource not accessible by integration"})
        if request.url.path == "/repos/acme/app/pulls/2/files":
            attempts["transient"] += 1
            if attempts["transient"] < 3:
                return httpx.Response(503, json={"message": "Upstream unavailable"})
            return httpx.Response(
                200,
                json=[
                    {
                        "filename": "src/main.py",
                        "status": "modified",
                        "additions": 3,
                        "deletions": 1,
                        "changes": 4,
                    }
                ],
            )
        if request.url.path == "/repos/acme/app/pulls/3/files":
            return httpx.Response(502, json={"message": "Bad Gateway"})
        return httpx.Response(404)

    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        transport=httpx.MockTransport(handler),
        max_retries=2,
        sleep_fn=lambda sec: sleeps.append(sec),
    ) as client:
        with pytest.raises(GitHubNotFoundError) as nf:
            client.get_installation(404)
        assert nf.value.retryable is False

        with pytest.raises(GitHubRateLimitError) as rl:
            client.get_installation(429)
        assert rl.value.retryable is True
        assert rl.value.retry_after_sec == 45
        assert tok not in str(rl.value)

        with pytest.raises(GitHubPermissionError) as perm:
            client.list_pull_request_files(5, "acme/app", 1)
        assert perm.value.retryable is False

        # Transient 503 succeeds on 3rd attempt
        files = client.list_pull_request_files(5, "acme/app", 2)
        assert len(files) == 1 and files[0].filename == "src/main.py"
        assert sleeps == [0.5, 1.0]

        # Exhausted transient 502 raises retryable error
        with pytest.raises(GitHubTransientError) as tr:
            client.list_pull_request_files(5, "acme/app", 3)
        assert tr.value.retryable is True

    # Verify secret redaction helper strips tokens, JWTs, and PEMs
    sample_jwt = "Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxIn0.c2lnbmF0dXJl"
    redacted = redact_github_secrets(f"{sample_jwt} token={tok} key={pkcs1_pem}")
    assert tok not in redacted
    assert "c2lnbmF0dXJl" not in redacted
    assert "BEGIN RSA PRIVATE KEY" not in redacted

    # Unconfigured settings fail closed
    with pytest.raises(GitHubConfigurationError):
        GitHubAppClient.from_settings(Settings(GITHUB_APP_ID=None, GITHUB_APP_PRIVATE_KEY=None))


def test_file_content_fetch_and_bounds(rsa_keypair: RSAPrivateKey) -> None:
    tok = _synthetic_inst_token("filetoken0000000000")
    raw_py = base64.b64encode(b"print('hello')\n").decode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/5/access_tokens":
            return httpx.Response(201, json={"token": tok})
        if request.url.path == "/repos/acme/app/contents/src/ok.py":
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "size": 15,
                    "encoding": "base64",
                    "content": raw_py,
                    "sha": "abc",
                },
            )
        if request.url.path == "/repos/acme/app/contents/big.bin":
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "size": 500_000,
                    "encoding": "base64",
                    "content": "",
                    "sha": "big",
                },
            )
        if request.url.path == "/repos/acme/app/contents/link":
            return httpx.Response(200, json={"type": "symlink", "size": 10})
        return httpx.Response(404)

    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        transport=httpx.MockTransport(handler),
        sleep_fn=lambda _s: None,
    ) as client:
        ok = client.get_file_content(5, "acme/app", "src/ok.py", "a" * 40, max_bytes=1024)
        assert ok.content == b"print('hello')\n"
        assert ok.skip_reason is None

        big = client.get_file_content(5, "acme/app", "big.bin", "a" * 40, max_bytes=1024)
        assert big.content is None
        assert big.skip_reason == "file_too_large"

        sym = client.get_file_content(5, "acme/app", "link", "a" * 40, max_bytes=1024)
        assert sym.content is None
        assert sym.skip_reason == "unsupported_entry_type_symlink"

        missing = client.get_file_content(5, "acme/app", "missing.py", "a" * 40, max_bytes=1024)
        assert missing.content is None
        assert missing.skip_reason == "not_found_at_ref"


def _base64url_decode_segment(segment: str) -> bytes:
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def test_rs256_independent_dotnet_rsa_verification(
    rsa_keypair: RSAPrivateKey,
    tmp_path: Path,
) -> None:
    """Cross-verify Sentinel RS256 signatures against independent .NET System.Security.Cryptography.RSA."""
    if sys.platform != "win32":
        pytest.skip("Windows .NET RSA verifier test runs on win32 hosts")
    powershell_exe = shutil.which("powershell.exe") or shutil.which("powershell")
    assert powershell_exe is not None, "powershell is required for independent RSA verification"

    token = create_github_app_jwt(4242, rsa_keypair, now=1_760_000_000, ttl_seconds=540)
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _base64url_decode_segment(sig_b64)

    mod_len = (rsa_keypair.n.bit_length() + 7) // 8
    half_len = mod_len // 2
    exp_len = (rsa_keypair.e.bit_length() + 7) // 8

    vector_path = tmp_path / "rsa_vector.json"
    vector_path.write_text(
        json.dumps(
            {
                "modulus": base64.b64encode(rsa_keypair.n.to_bytes(mod_len, "big")).decode("ascii"),
                "exponent": base64.b64encode(rsa_keypair.e.to_bytes(exp_len, "big")).decode(
                    "ascii"
                ),
                "d": base64.b64encode(rsa_keypair.d.to_bytes(mod_len, "big")).decode("ascii"),
                "p": base64.b64encode(rsa_keypair.p.to_bytes(half_len, "big")).decode("ascii"),
                "q": base64.b64encode(rsa_keypair.q.to_bytes(half_len, "big")).decode("ascii"),
                "dp": base64.b64encode(rsa_keypair.dp.to_bytes(half_len, "big")).decode("ascii"),
                "dq": base64.b64encode(rsa_keypair.dq.to_bytes(half_len, "big")).decode("ascii"),
                "qinv": base64.b64encode(rsa_keypair.qinv.to_bytes(half_len, "big")).decode(
                    "ascii"
                ),
                "msg": base64.b64encode(signing_input).decode("ascii"),
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )

    quoted_path = "'" + str(vector_path).replace("'", "''") + "'"
    ps_script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$data = Get-Content -LiteralPath {quoted_path} -Raw | ConvertFrom-Json",
            "$rsa = [System.Security.Cryptography.RSA]::Create()",
            "$params = New-Object System.Security.Cryptography.RSAParameters",
            "$params.Modulus = [Convert]::FromBase64String($data.modulus)",
            "$params.Exponent = [Convert]::FromBase64String($data.exponent)",
            "$params.D = [Convert]::FromBase64String($data.d)",
            "$params.P = [Convert]::FromBase64String($data.p)",
            "$params.Q = [Convert]::FromBase64String($data.q)",
            "$params.DP = [Convert]::FromBase64String($data.dp)",
            "$params.DQ = [Convert]::FromBase64String($data.dq)",
            "$params.InverseQ = [Convert]::FromBase64String($data.qinv)",
            "$rsa.ImportParameters($params)",
            "$msg = [Convert]::FromBase64String($data.msg)",
            "$sig = [Convert]::FromBase64String($data.sig)",
            "$tampered = [byte[]]$msg.Clone()",
            "$tampered[0] = $tampered[0] -bxor 0x01",
            "$ok = $rsa.VerifyData($msg, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)",
            "$bad = $rsa.VerifyData($tampered, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)",
            "$dotnetSig = $rsa.SignData($msg, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)",
            "@{ verified = $ok; tampered_verified = $bad; dotnet_sig = [Convert]::ToBase64String($dotnetSig) } | ConvertTo-Json -Compress",
        ]
    )
    encoded_cmd = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    proc = subprocess.run(
        [powershell_exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_cmd],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    result = json.loads(proc.stdout.strip())
    assert result["verified"] is True
    assert result["tampered_verified"] is False
    dotnet_sig = base64.b64decode(result["dotnet_sig"])
    assert dotnet_sig == sign_rs256(rsa_keypair, signing_input)
    assert verify_rs256(rsa_keypair.n, rsa_keypair.e, signing_input, dotnet_sig) is True


def test_crypto_rejects_crt_tampering_trailing_asn1_bool_and_excess_ttl(
    rsa_keypair: RSAPrivateKey,
) -> None:
    bad_dp = RSAPrivateKey(
        n=rsa_keypair.n,
        e=rsa_keypair.e,
        d=rsa_keypair.d,
        p=rsa_keypair.p,
        q=rsa_keypair.q,
        dp=rsa_keypair.dp - 1,
        dq=rsa_keypair.dq,
        qinv=rsa_keypair.qinv,
    )
    with pytest.raises(GitHubKeyError, match="CRT"):
        parse_rsa_private_key_pem(_encode_rsa_pkcs1_pem(bad_dp))

    bad_dq = RSAPrivateKey(
        n=rsa_keypair.n,
        e=rsa_keypair.e,
        d=rsa_keypair.d,
        p=rsa_keypair.p,
        q=rsa_keypair.q,
        dp=rsa_keypair.dp,
        dq=rsa_keypair.dq - 1,
        qinv=rsa_keypair.qinv,
    )
    with pytest.raises(GitHubKeyError, match="CRT"):
        parse_rsa_private_key_pem(_encode_rsa_pkcs1_pem(bad_dq))

    bad_qinv = RSAPrivateKey(
        n=rsa_keypair.n,
        e=rsa_keypair.e,
        d=rsa_keypair.d,
        p=rsa_keypair.p,
        q=rsa_keypair.q,
        dp=rsa_keypair.dp,
        dq=rsa_keypair.dq,
        qinv=(rsa_keypair.qinv + 1) % rsa_keypair.p,
    )
    with pytest.raises(GitHubKeyError, match="CRT"):
        parse_rsa_private_key_pem(_encode_rsa_pkcs1_pem(bad_qinv))

    # Trailing unexpected DER element inside PKCS#1 sequence (10 children instead of 9)
    pkcs1_fields = b"".join(
        _der_int(v)
        for v in (
            0,
            rsa_keypair.n,
            rsa_keypair.e,
            rsa_keypair.d,
            rsa_keypair.p,
            rsa_keypair.q,
            rsa_keypair.dp,
            rsa_keypair.dq,
            rsa_keypair.qinv,
        )
    )
    trailing_pkcs1_der = _der_tlv(0x30, pkcs1_fields + _der_tlv(0x04, b"extra"))
    b64_p1 = base64.b64encode(trailing_pkcs1_der).decode("ascii")
    pem_p1 = f"-----BEGIN RSA PRIVATE KEY-----\n{b64_p1}\n-----END RSA PRIVATE KEY-----"
    with pytest.raises(GitHubKeyError, match="field count"):
        parse_rsa_private_key_pem(pem_p1)

    # Trailing unexpected DER element inside PKCS#8 sequence (not [0] attributes)
    pkcs1_der = _der_tlv(0x30, pkcs1_fields)
    alg_id = _der_tlv(
        0x30,
        _der_tlv(0x06, bytes.fromhex("2a864886f70d010101")) + _der_tlv(0x05, b""),
    )
    trailing_pkcs8_der = _der_tlv(
        0x30,
        _der_int(0) + alg_id + _der_tlv(0x04, pkcs1_der) + _der_tlv(0x04, b"junk"),
    )
    b64_p8 = base64.b64encode(trailing_pkcs8_der).decode("ascii")
    pem_p8 = f"-----BEGIN PRIVATE KEY-----\n{b64_p8}\n-----END PRIVATE KEY-----"
    with pytest.raises(GitHubKeyError):
        parse_rsa_private_key_pem(pem_p8)

    with pytest.raises(ValueError, match="positive integer"):
        create_github_app_jwt(True, rsa_keypair)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="540"):
        create_github_app_jwt(10, rsa_keypair, now=1_760_000_000, ttl_seconds=600)

    max_valid = create_github_app_jwt(10, rsa_keypair, now=1_760_000_000, ttl_seconds=540)
    claims = json.loads(_base64url_decode_segment(max_valid.split(".")[1]).decode("utf-8"))
    assert claims["exp"] - claims["iat"] == 600


def test_installation_token_refresh_stampede_and_stale_401_protection(
    rsa_keypair: RSAPrivateKey,
) -> None:
    refresh_calls = 0
    refresh_gate = threading.Event()
    tok_first = _synthetic_inst_token("concurrent1111111111")
    tok_second = _synthetic_inst_token("concurrent2222222222")

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal refresh_calls
        if request.url.path == "/app/installations/42/access_tokens":
            refresh_calls += 1
            refresh_gate.wait(timeout=2.0)
            tok = tok_first if refresh_calls == 1 else tok_second
            exp = (datetime.now(UTC) + timedelta(minutes=20)).isoformat().replace("+00:00", "Z")
            return httpx.Response(201, json={"token": tok, "expires_at": exp})
        raise AssertionError(f"Unexpected path {request.url.path}")

    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        transport=httpx.MockTransport(handler),
        sleep_fn=lambda _s: None,
    ) as client:
        barrier = threading.Barrier(4)
        results: list[str] = []
        results_lock = threading.Lock()

        def worker() -> None:
            barrier.wait(timeout=2.0)
            token = client.get_installation_token(42)
            with results_lock:
                results.append(token)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.05)
        refresh_gate.set()
        for t in threads:
            t.join(timeout=5.0)

        assert refresh_calls == 1
        assert results == [tok_first] * 4

        # Stale failed_token must NOT evict newer cached token; matching token MUST evict it.
        client._invalidate_installation_token(42, tok_second)
        assert client.get_installation_token(42) == tok_first
        assert refresh_calls == 1

        client._invalidate_installation_token(42, tok_first)
        assert client.get_installation_token(42) == tok_second
        assert refresh_calls == 2


def test_bounded_streaming_link_hardening_and_jwt_redaction(
    rsa_keypair: RSAPrivateKey,
) -> None:
    tok = _synthetic_inst_token("streamtest1111111111")

    class _ChunkedLargeStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"type":"file","encoding":"base64","size":10,"content":"'
            for _ in range(8):
                yield b"A" * 40_000
            yield b'"}'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/5/access_tokens":
            return httpx.Response(201, json={"token": tok})
        if request.url.path.endswith("/contents/huge_stream.py"):
            return httpx.Response(200, stream=_ChunkedLargeStream())
        if request.url.path == "/installation/repositories":
            if "fragment" in str(request.url):
                return httpx.Response(
                    200,
                    headers={
                        "Link": '<https://api.github.com/installation/repositories?page=2#frag>; rel="next"'
                    },
                    json={"repositories": []},
                )
            if "traversal" in str(request.url):
                return httpx.Response(
                    200,
                    headers={
                        "Link": '<https://api.github.com/installation/repositories/../orgs/acme/repos?page=2>; rel="next"'
                    },
                    json={"repositories": []},
                )
            return httpx.Response(
                200,
                headers={"Link": '<https://api.github.com/user/repos?page=2>; rel="next"'},
                json={"repositories": []},
            )
        raise AssertionError(f"Unexpected path {request.url.path}")

    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        transport=httpx.MockTransport(handler),
        sleep_fn=lambda _s: None,
    ) as client:
        # 320 KB streamed body exceeds 256 KB buffer floor for max_bytes=1024 -> skipped non-fatally
        huge = client.get_file_content(5, "acme/app", "huge_stream.py", "a" * 40, max_bytes=1024)
        assert huge.content is None
        assert huge.skip_reason == "file_too_large"

        # Strict max_response_bytes on _request_with_retry aborts oversized JSON before full buffering
        with pytest.raises(GitHubClientError, match="safety limit"):
            client._request_with_retry(
                "GET",
                "/repos/acme/app/contents/huge_stream.py?ref=" + ("a" * 40),
                token_provider=lambda: tok,
                max_response_bytes=1024,
            )

        # Link header pointing at a different API endpoint is rejected
        with pytest.raises(GitHubValidationError, match="target path mismatch"):
            client.list_installation_repositories(5)

    # Link parser rejects fragment and traversal segments even if prefix matches
    from app.services.github_client import _parse_next_link

    with pytest.raises(GitHubValidationError, match="fragment"):
        _parse_next_link(
            '<https://api.github.com/installation/repositories?page=2#sec>; rel="next"',
            base_scheme="https",
            base_netloc="api.github.com",
            base_path_prefix="",
            expected_rel_path="/installation/repositories",
        )
    with pytest.raises(GitHubValidationError, match="traversal"):
        _parse_next_link(
            '<https://api.github.com/installation/repositories/../repos?page=2>; rel="next"',
            base_scheme="https",
            base_netloc="api.github.com",
            base_path_prefix="",
            expected_rel_path="/installation/repositories",
        )

    # Bare JWT (without "Bearer ") and GitHub PATs are redacted in both client and job service
    sample_jwt = create_github_app_jwt(99, rsa_keypair, now=1_760_000_000)
    raw_pat = "github" + "_pat_" + "1234567890abcdef"
    raw_msg = f"Failed using token={tok} pat={raw_pat} jwt={sample_jwt}"
    redacted_client = redact_github_secrets(raw_msg)
    redacted_job = sanitize_failure_message(raw_msg)
    for secret in (tok, raw_pat, sample_jwt):
        assert secret not in redacted_client
        assert secret not in redacted_job


def test_oauth_code_exchange_and_secret_redaction(
    rsa_keypair: RSAPrivateKey,
) -> None:
    from urllib.parse import parse_qs

    from app.services.github_client import GitHubOAuthError

    user_tok = "ghu" + "_" + "oauthuser1234567890abcdef"
    client_secret_val = "oauth_secret_sentinel_test_value_987654"
    recorded_forms: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/login/oauth/access_token"
        assert request.headers["accept"] == "application/json"
        form = parse_qs(request.content.decode("utf-8"))
        recorded_forms.append(form)
        code = form["code"][0]
        if code == "good-code":
            return httpx.Response(
                200,
                json={"access_token": user_tok, "token_type": "bearer", "scope": ""},
            )
        if code == "bad-code":
            return httpx.Response(
                200,
                json={
                    "error": "bad_verification_code",
                    "error_description": "The code passed is incorrect or expired.",
                },
            )
        if code == "bad-creds":
            return httpx.Response(
                200,
                json={"error": "incorrect_client_credentials"},
            )
        if code == "wrong-type":
            return httpx.Response(
                200,
                json={"access_token": user_tok, "token_type": "mac"},
            )
        if code == "empty-token":
            return httpx.Response(200, json={"token_type": "bearer"})
        if code == "rate-limited":
            return httpx.Response(429, json={"message": "slow down"})
        return httpx.Response(502, json={"message": "bad gateway"})

    # With redirect_uri configured
    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        oauth_base_url="https://github.com",
        client_id="Iv1.testclientid",
        client_secret=client_secret_val,
        oauth_redirect_uri="https://sentinel.example.com/integrations/github/callback",
        transport=httpx.MockTransport(handler),
        sleep_fn=lambda _s: None,
    ) as client:
        assert client_secret_val not in repr(client)
        assert client_secret_val not in str(client)

        token = client.exchange_oauth_code("good-code")
        assert token == user_tok
        assert recorded_forms[-1]["client_id"] == ["Iv1.testclientid"]
        assert recorded_forms[-1]["client_secret"] == [client_secret_val]
        assert recorded_forms[-1]["redirect_uri"] == [
            "https://sentinel.example.com/integrations/github/callback"
        ]

        with pytest.raises(GitHubOAuthError, match="invalid, expired, or denied"):
            client.exchange_oauth_code("bad-code")

        with pytest.raises(GitHubConfigurationError, match="rejected"):
            client.exchange_oauth_code("bad-creds")

        with pytest.raises(GitHubOAuthError, match="token_type"):
            client.exchange_oauth_code("wrong-type")

        with pytest.raises(GitHubOAuthError, match="access token"):
            client.exchange_oauth_code("empty-token")

        with pytest.raises(GitHubRateLimitError):
            client.exchange_oauth_code("rate-limited")

        with pytest.raises(GitHubTransientError):
            client.exchange_oauth_code("upstream-502")

        with pytest.raises(GitHubOAuthError, match="Invalid GitHub OAuth authorization code"):
            client.exchange_oauth_code("   ")

    # Without redirect_uri configured, redirect_uri is omitted from form payload
    recorded_forms.clear()
    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        oauth_base_url="https://github.com",
        client_id="Iv1.testclientid",
        client_secret=client_secret_val,
        oauth_redirect_uri=None,
        transport=httpx.MockTransport(handler),
        sleep_fn=lambda _s: None,
    ) as client_no_redir:
        assert client_no_redir.exchange_oauth_code("good-code") == user_tok
        assert "redirect_uri" not in recorded_forms[0]

    # Missing OAuth credentials fails closed
    with (
        GitHubAppClient(
            app_id=10,
            private_key=rsa_keypair,
            transport=httpx.MockTransport(handler),
            sleep_fn=lambda _s: None,
        ) as unconfigured_client,
        pytest.raises(GitHubConfigurationError, match="not configured"),
    ):
        unconfigured_client.exchange_oauth_code("good-code")

    # redact_github_secrets scrubs client_secret, access_token, refresh_token, and ghu_ tokens
    refresh_tok = "ghr" + "_" + "refresh999"
    raw_oauth_err = (
        f"client_secret={client_secret_val}&access_token={user_tok}&refresh_token={refresh_tok}"
    )
    scrubbed = redact_github_secrets(raw_oauth_err)
    assert client_secret_val not in scrubbed
    assert user_tok not in scrubbed
    assert refresh_tok not in scrubbed


def test_get_oauth_user_and_list_user_installations(
    rsa_keypair: RSAPrivateKey,
) -> None:
    from app.services.github_client import GitHubAuthenticationError, GitHubOAuthUser

    user_tok = "ghu" + "_" + "oauthuser9876543210"
    revoked_tok = "ghu" + "_" + "revokedtoken12345"
    bad_shape_tok = "ghu" + "_" + "badshapetoken12345"
    ssrf_link_tok = "ghu" + "_" + "ssrflinktoken12345"

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if request.url.path == "/user":
            if auth == f"Bearer {revoked_tok}":
                return httpx.Response(401, json={"message": "Bad credentials"})
            if auth == f"Bearer {bad_shape_tok}":
                return httpx.Response(200, json={"id": "not-an-int", "login": ""})
            assert auth == f"Bearer {user_tok}"
            return httpx.Response(200, json={"id": 101, "login": "alice"})

        if request.url.path == "/user/installations":
            if auth == f"Bearer {revoked_tok}":
                return httpx.Response(403, json={"message": "Token lacks access"})
            if auth == f"Bearer {ssrf_link_tok}":
                return httpx.Response(
                    200,
                    headers={
                        "Link": '<https://api.github.com/app/installations?page=2>; rel="next"'
                    },
                    json={"installations": []},
                )
            page = request.url.params.get("page")
            if page is None:
                return httpx.Response(
                    200,
                    headers={
                        "Link": '<https://api.github.com/user/installations?per_page=100&page=2>; rel="next"'
                    },
                    json={
                        "installations": [
                            {
                                "id": 555,
                                "account": {
                                    "id": 5001,
                                    "login": "acme-org",
                                    "type": "Organization",
                                },
                                "permissions": {"contents": "read", "pull_requests": "write"},
                                "repository_selection": "selected",
                                "suspended_at": None,
                            }
                        ]
                    },
                )
            assert page == "2"
            return httpx.Response(
                200,
                json={
                    "installations": [
                        {
                            "id": 777,
                            "account": {"id": 101, "login": "alice", "type": "User"},
                            "permissions": {"contents": "read", "pull_requests": "read"},
                            "repository_selection": "all",
                            "suspended_at": None,
                        }
                    ]
                },
            )
        raise AssertionError(f"Unexpected path {request.url.path}")

    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        transport=httpx.MockTransport(handler),
        sleep_fn=lambda _s: None,
    ) as client:
        oauth_user = client.get_oauth_user(user_tok)
        assert oauth_user == GitHubOAuthUser(id=101, login="alice")

        with pytest.raises(GitHubAuthenticationError):
            client.get_oauth_user(revoked_tok)

        with pytest.raises(GitHubClientError):
            client.get_oauth_user(bad_shape_tok)

        installs = client.list_user_installations(user_tok)
        assert [inst.id for inst in installs] == [555, 777]
        assert installs[0].account_type == "Organization"
        assert installs[0].account_id == 5001
        assert installs[0].account_login == "acme-org"
        assert installs[1].account_type == "User"

        with pytest.raises(GitHubPermissionError):
            client.list_user_installations(revoked_tok)

        with pytest.raises(GitHubValidationError, match="target path mismatch"):
            client.list_user_installations(ssrf_link_tok)


@pytest.mark.parametrize(
    "bad_url",
    [
        "",
        "   ",
        "https://api.github.com/bad path",
        "https://api.github.com\nhttps://evil.example.com",
        "https://user:pass@api.github.com",
        "https://token@api.github.com",
        "https://api.github.com?foo=bar",
        "https://api.github.com#fragment",
        "ftp://api.github.com",
        "api.github.com",
        "https://",
        "https://:443",
        "https://api.github.com:99999",
        "https://ghe.example.com/api/../v3",
        "https://ghe.example.com\\api\\v3",
    ],
)
def test_client_init_rejects_invalid_base_and_oauth_urls(
    rsa_keypair: RSAPrivateKey,
    bad_url: str,
) -> None:
    from pydantic import ValidationError

    with pytest.raises(GitHubConfigurationError):
        GitHubAppClient(app_id=10, private_key=rsa_keypair, base_url=bad_url)

    with pytest.raises(GitHubConfigurationError):
        GitHubAppClient(app_id=10, private_key=rsa_keypair, oauth_base_url=bad_url)

    with pytest.raises(ValidationError):
        Settings(GITHUB_API_BASE_URL=bad_url)

    with pytest.raises(ValidationError):
        Settings(GITHUB_OAUTH_BASE_URL=bad_url)


def test_client_init_https_enforcement_and_github_enterprise_urls(
    rsa_keypair: RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Non-production allows http:// URLs for local test servers
    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        base_url="http://localhost:8080/api/v3/",
        oauth_base_url="http://localhost:8080/",
        require_https=False,
    ) as local_client:
        assert local_client.base_url == "http://localhost:8080/api/v3"
        assert local_client._oauth_base_url == "http://localhost:8080"

    # Production mode enforces HTTPS even on direct GitHubAppClient construction
    with pytest.raises(GitHubConfigurationError, match="HTTPS"):
        GitHubAppClient(
            app_id=10,
            private_key=rsa_keypair,
            base_url="http://api.github.com",
            require_https=True,
        )

    with pytest.raises(GitHubConfigurationError, match="HTTPS"):
        GitHubAppClient(
            app_id=10,
            private_key=rsa_keypair,
            oauth_base_url="http://github.com",
            require_https=True,
        )

    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(GitHubConfigurationError, match="HTTPS"):
        GitHubAppClient(
            app_id=10,
            private_key=rsa_keypair,
            base_url="http://ghe.internal/api/v3",
        )
    with pytest.raises(GitHubConfigurationError, match="HTTPS"):
        GitHubAppClient(
            app_id=10,
            private_key=rsa_keypair,
            oauth_base_url="http://ghe.internal",
        )
    monkeypatch.delenv("APP_ENV", raising=False)

    # Valid GitHub Enterprise Server URLs with path prefix work end-to-end
    user_tok = "ghu" + "_" + "gheuser1234567890"
    recorded_urls: list[str] = []

    def ghe_handler(request: httpx.Request) -> httpx.Response:
        recorded_urls.append(str(request.url))
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": user_tok, "token_type": "bearer"})
        if request.url.path == "/api/v3/app/installations/42":
            return httpx.Response(
                200,
                json={
                    "id": 42,
                    "account": {"id": 500, "login": "enterprise-org", "type": "Organization"},
                    "permissions": {"contents": "read", "pull_requests": "write"},
                    "suspended_at": None,
                },
            )
        raise AssertionError(f"Unexpected GHES URL {request.url}")

    with GitHubAppClient(
        app_id=10,
        private_key=rsa_keypair,
        base_url="https://ghe.example.com/api/v3/",
        oauth_base_url="https://ghe.example.com/",
        client_id="Iv1.gheclient",
        client_secret="ghe_secret_value_1234567890",
        require_https=True,
        transport=httpx.MockTransport(ghe_handler),
        sleep_fn=lambda _s: None,
    ) as ghe_client:
        assert ghe_client.base_url == "https://ghe.example.com/api/v3"
        assert ghe_client._base_path_prefix == "/api/v3"
        assert ghe_client._oauth_base_url == "https://ghe.example.com"
        inst = ghe_client.get_installation(42)
        assert inst.id == 42
        assert inst.account_login == "enterprise-org"
        assert ghe_client.exchange_oauth_code("ghe-code") == user_tok
        assert recorded_urls == [
            "https://ghe.example.com/api/v3/app/installations/42",
            "https://ghe.example.com/login/oauth/access_token",
        ]


def test_github_oauth_client_from_oauth_settings_without_app_key_and_redirect_override() -> None:
    """GitHubOAuthClient works with client credentials only and honors redirect_uri overrides."""
    oauth_tok = "ghu" + "_" + "oauthclientonly123456"
    seen_forms: list[str] = []

    def oauth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            seen_forms.append(request.content.decode("utf-8"))
            return httpx.Response(200, json={"access_token": oauth_tok, "token_type": "bearer"})
        if request.url.path == "/user":
            return httpx.Response(
                200,
                json={
                    "id": 707,
                    "login": "carol",
                    "name": "Carol Security",
                    "avatar_url": "https://avatars.githubusercontent.com/u/707?v=4",
                },
            )
        raise AssertionError(f"Unexpected path {request.url.path}")

    settings = Settings(
        GITHUB_CLIENT_ID="Iv1.oauthonlyclient",
        GITHUB_CLIENT_SECRET=SecretStr("oauth_only_client_secret_value_12345"),
        GITHUB_AUTH_CALLBACK_URL="https://sentinel.example.com/auth/github/callback",
    )
    assert not settings.is_github_app_configured()
    assert settings.is_github_oauth_configured()

    with GitHubOAuthClient.from_oauth_settings(
        settings,
        transport=httpx.MockTransport(oauth_handler),
        sleep_fn=lambda _s: None,
    ) as oauth_client:
        auth_url = oauth_client.build_oauth_authorize_url(state="state-abc")
        assert auth_url.startswith("https://github.com/login/oauth/authorize?")
        assert "client_id=Iv1.oauthonlyclient" in auth_url
        assert "state=state-abc" in auth_url
        assert (
            "redirect_uri=https%3A%2F%2Fsentinel.example.com%2Fauth%2Fgithub%2Fcallback" in auth_url
        )

        assert oauth_client.exchange_oauth_code("code-default") == oauth_tok
        assert (
            oauth_client.exchange_oauth_code(
                "code-override",
                redirect_uri="https://sentinel.example.com/custom/callback",
            )
            == oauth_tok
        )
        assert (
            oauth_client.exchange_oauth_code("code-explicit-none", redirect_uri=None) == oauth_tok
        )
        assert oauth_client.exchange_oauth_code("code-explicit-none", redirect_uri=None) == oauth_tok
        assert oauth_client.get_oauth_user(oauth_tok) == GitHubOAuthUser(
            id=707,
            login="carol",
            name="Carol Security",
            avatar_url="https://avatars.githubusercontent.com/u/707?v=4",
        )

    assert (
        "redirect_uri=https%3A%2F%2Fsentinel.example.com%2Fauth%2Fgithub%2Fcallback"
        in seen_forms[0]
    )
    assert "redirect_uri=https%3A%2F%2Fsentinel.example.com%2Fcustom%2Fcallback" in seen_forms[1]
    assert "redirect_uri=" not in seen_forms[2]


def test_github_oauth_user_ignores_non_https_avatar_url() -> None:
    oauth_tok = "ghu" + "_" + "insecureavatar123456"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(
                200,
                json={
                    "id": 808,
                    "login": "dave",
                    "name": "Dave",
                    "avatar_url": "javascript:alert(1)",
                },
            )
        raise AssertionError(f"Unexpected path {request.url.path}")

    with GitHubOAuthClient(
        client_id="Iv1.test",
        client_secret="oauth_only_client_secret_value_12345",
        transport=httpx.MockTransport(handler),
        sleep_fn=lambda _s: None,
    ) as client:
        assert client.get_oauth_user(oauth_tok) == GitHubOAuthUser(
            id=808,
            login="dave",
            name="Dave",
            avatar_url=None,
        )
