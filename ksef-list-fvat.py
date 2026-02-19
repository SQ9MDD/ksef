#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


DEFAULT_BASE_URL = "https://api.ksef.mf.gov.pl/api/v2"  # produkcja (API 2.0)


@dataclass
class Challenge:
    challenge: str
    timestamp_iso: str
    timestamp_ms: int


def _http_json(method: str, url: str, *, headers: Optional[dict] = None, json_body: Any = None, timeout: int = 30):
    r = requests.request(method, url, headers=headers, json=json_body, timeout=timeout)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} {url}\n{r.text}")
    if r.text.strip() == "":
        return None
    return r.json()


def get_challenge(base_url: str) -> Challenge:
    data = _http_json("POST", f"{base_url}/auth/challenge", json_body={})
    ch = data["challenge"]
    ts = data["timestamp"]  # ISO, zwykle z +00:00
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    ts_ms = int(dt.timestamp() * 1000)
    return Challenge(challenge=ch, timestamp_iso=ts, timestamp_ms=ts_ms)


def get_ksef_token_encryption_pubkey(base_url: str):
    """
    GET /security/public-key-certificates
    Wybiera certyfikat do szyfrowania tokena (usage zawiera zwykle 'KsefTokenEncryption' albo podobnie).
    """
    certs = _http_json("GET", f"{base_url}/security/public-key-certificates")
    if not isinstance(certs, list) or not certs:
        raise RuntimeError("Brak certyfikatów z /security/public-key-certificates")

    def score(c: dict) -> int:
        usage = c.get("usage")
        usage_list = usage if isinstance(usage, list) else [usage] if isinstance(usage, str) else []
        u = " ".join([str(x) for x in usage_list]).lower()
        s = 0
        if "token" in u:
            s += 10
        if "ksef" in u:
            s += 3
        if "encr" in u:
            s += 3
        return s

    certs_sorted = sorted(certs, key=score, reverse=True)
    best = certs_sorted[0]

    cert_b64 = best.get("certificate") or best.get("cert") or best.get("x509Certificate")
    if not cert_b64:
        raise RuntimeError("Nie znalazłem pola certificate w odpowiedzi /security/public-key-certificates")

    cert_der = base64.b64decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_key()


def encrypt_token_with_timestamp(pubkey, token: str, timestamp_ms: int) -> str:
    plaintext = f"{token}|{timestamp_ms}".encode("utf-8")
    ciphertext = pubkey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("ascii")


def authenticate_ksef_token(base_url: str, context_nip: str, token: str) -> Tuple[str, str]:
    """
    Zwraca (authenticationToken, referenceNumber)
    """
    ch = get_challenge(base_url)
    pubkey = get_ksef_token_encryption_pubkey(base_url)
    encrypted_b64 = encrypt_token_with_timestamp(pubkey, token, ch.timestamp_ms)

    req = {
        "challenge": ch.challenge,
        "contextIdentifier": {"type": "nip", "value": context_nip},
        "encryptedToken": encrypted_b64,
        "authorizationPolicy": None,
    }
    resp = _http_json("POST", f"{base_url}/auth/ksef-token", json_body=req)
    auth_token = resp["authenticationToken"]["token"] if isinstance(resp.get("authenticationToken"), dict) else resp.get("authenticationToken")
    ref = resp["referenceNumber"]
    return auth_token, ref


def wait_for_auth_finished(base_url: str, authentication_token: str, reference_number: str, timeout_s: int = 60) -> dict:
    """
    Poll GET /auth/{referenceNumber} aż status wskazuje sukces.
    """
    headers = {"Authorization": f"Bearer {authentication_token}"}
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = _http_json("GET", f"{base_url}/auth/{reference_number}", headers=headers)
        # Zwykle: {"status":{"code":200,"description":"..."}, ...}
        st = (last or {}).get("status") or {}
        code = st.get("code")
        if code == 200:
            return last
        if code in (400, 401, 403, 450, 500):
            raise RuntimeError(f"Uwierzytelnianie zakończone błędem: {json.dumps(last, ensure_ascii=False)}")
        time.sleep(1.0)
    raise RuntimeError(f"Timeout oczekiwania na uwierzytelnienie. Ostatnia odpowiedź: {json.dumps(last, ensure_ascii=False)}")


def redeem_tokens(base_url: str, authentication_token: str) -> Tuple[str, str]:
    headers = {"Authorization": f"Bearer {authentication_token}"}
    resp = _http_json("POST", f"{base_url}/auth/token/redeem", headers=headers, json_body={})
    access_token = resp.get("accessToken") or (resp.get("accessToken", {}) if isinstance(resp.get("accessToken"), dict) else None)
    refresh_token = resp.get("refreshToken") or (resp.get("refreshToken", {}) if isinstance(resp.get("refreshToken"), dict) else None)
    if isinstance(access_token, dict):
        access_token = access_token.get("token")
    if isinstance(refresh_token, dict):
        refresh_token = refresh_token.get("token")
    if not access_token:
        raise RuntimeError(f"Brak accessToken w odpowiedzi redeem: {json.dumps(resp, ensure_ascii=False)}")
    return access_token, (refresh_token or "")


def query_invoice_metadata(
    base_url: str,
    access_token: str,
    subject_type: str,
    date_type: str,
    date_from: str,
    date_to: str,
    page_offset: int,
    page_size: int,
) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    body = {
        "subjectType": subject_type,
        "dateRange": {
            "from": date_from,
            "to": date_to,
            "dateType": date_type,
        },
    }
    params = f"?pageOffset={page_offset}&pageSize={page_size}"
    return _http_json("POST", f"{base_url}/invoices/query/metadata{params}", headers=headers, json_body=body)


def pick_fields(row: dict) -> dict:
    # Metadane mogą mieć różne nazwy pól, więc wybieramy kilka typowych
    keys = [
        "ksefNumber",
        "invoiceKsefNumber",
        "invoiceNumber",
        "issueDate",
        "invoicingDate",
        "acquisitionTimestamp",
        "sellerNip",
        "supplierNip",
        "buyerNip",
        "netAmount",
        "grossAmount",
        "currency",
    ]
    out = {}
    for k in keys:
        if k in row and row[k] not in (None, ""):
            out[k] = row[k]
    return out or row


def main():
    ap = argparse.ArgumentParser(description="KSeF API 2.0 PoC: lista metadanych faktur otrzymanych (Subject2)")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help="np. https://api.ksef.mf.gov.pl/api/v2")
    ap.add_argument("--nip", required=True, help="NIP kontekstu (Twojej firmy)")
    ap.add_argument("--token", required=True, help="Token KSeF z MCU (sekret)")
    ap.add_argument("--subject-type", default="Subject2", help="Subject2 = faktury otrzymane (kosztowe)")
    ap.add_argument("--date-type", default="Issue", help="np. Issue albo Invoicing (zależnie od potrzeb)")
    ap.add_argument("--from", dest="date_from", default=None, help="ISO, np. 2026-02-01T00:00:00+00:00")
    ap.add_argument("--to", dest="date_to", default=None, help="ISO, np. 2026-02-18T23:59:59+00:00")
    ap.add_argument("--page-size", type=int, default=20)
    ap.add_argument("--page-offset", type=int, default=0)
    args = ap.parse_args()

    # domyślny zakres: ostatnie 30 dni UTC
    now = datetime.now(timezone.utc)
    if not args.date_to:
        args.date_to = now.isoformat()
    if not args.date_from:
        args.date_from = (now - timedelta(days=30)).isoformat()

    auth_token, ref = authenticate_ksef_token(args.base_url, args.nip, args.token)
    wait_for_auth_finished(args.base_url, auth_token, ref, timeout_s=90)
    access_token, _refresh = redeem_tokens(args.base_url, auth_token)

    resp = query_invoice_metadata(
        args.base_url,
        access_token,
        args.subject_type,
        args.date_type,
        args.date_from,
        args.date_to,
        args.page_offset,
        args.page_size,
    )

    # Odpowiedź zwykle ma listę w jakimś polu, ale nie zgadujemy na sztywno.
    # Spróbujmy znaleźć pierwszą listę obiektów w strukturze.
    rows = None
    if isinstance(resp, dict):
        for v in resp.values():
            if isinstance(v, list):
                rows = v
                break

    if not rows:
        print(json.dumps(resp, ensure_ascii=False, indent=2))
        return

    for i, r in enumerate(rows, 1):
        if isinstance(r, dict):
            print(f"{i}. {json.dumps(pick_fields(r), ensure_ascii=False)}")
        else:
            print(f"{i}. {r}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
