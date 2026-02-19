#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


BASE_URL = "https://api.ksef.mf.gov.pl/v2"


@dataclass
class Challenge:
    challenge: str
    timestamp_ms: int


def http_json(method, url, headers=None, json_body=None):
    r = requests.request(method, url, headers=headers, json=json_body, timeout=60)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")
    return r.json() if r.text.strip() else None


def get_challenge():
    data = http_json("POST", f"{BASE_URL}/auth/challenge", json_body={})
    ts = data["timestamp"].replace("Z", "+00:00")
    dt = datetime.fromisoformat(ts)
    return Challenge(
        challenge=data["challenge"],
        timestamp_ms=int(dt.timestamp() * 1000),
    )


def get_encryption_pubkey():
    certs = http_json("GET", f"{BASE_URL}/security/public-key-certificates")
    cert_b64 = certs[0]["certificate"]
    cert_der = base64.b64decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_key()


def encrypt_token(pubkey, token, timestamp_ms):
    payload = f"{token}|{timestamp_ms}".encode("utf-8")
    encrypted = pubkey.encrypt(
        payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted).decode("ascii")


def authenticate(nip, token):
    ch = get_challenge()
    pubkey = get_encryption_pubkey()
    encrypted_token = encrypt_token(pubkey, token, ch.timestamp_ms)

    req = {
        "challenge": ch.challenge,
        "contextIdentifier": {"type": "nip", "value": nip},
        "encryptedToken": encrypted_token,
        "authorizationPolicy": None,
    }

    resp = http_json("POST", f"{BASE_URL}/auth/ksef-token", json_body=req)
    auth_token = resp["authenticationToken"]["token"]
    ref = resp["referenceNumber"]

    headers = {"Authorization": f"Bearer {auth_token}"}

    # czekamy aż status będzie 200
    for _ in range(60):
        status = http_json("GET", f"{BASE_URL}/auth/{ref}", headers=headers)
        if status["status"]["code"] == 200:
            break
        time.sleep(1)
    else:
        raise RuntimeError("Timeout uwierzytelnienia")

    redeem = http_json("POST", f"{BASE_URL}/auth/token/redeem", headers=headers, json_body={})
    return redeem["accessToken"]["token"]


def download_invoice(access_token, ksef_number, output_path):
    url = f"{BASE_URL}/invoices/ksef/{ksef_number}"
    headers = {"Authorization": f"Bearer {access_token}"}

    r = requests.get(url, headers=headers, stream=True, timeout=60)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")

    with open(output_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)


def main():
    parser = argparse.ArgumentParser(description="Pobierz fakturę XML z KSeF po numerze KSeF")
    parser.add_argument("--nip", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--ksef-number", required=True)
    parser.add_argument("--out", default="faktura.xml")
    args = parser.parse_args()

    print("Uwierzytelnianie...")
    access_token = authenticate(args.nip, args.token)

    print("Pobieranie faktury...")
    download_invoice(access_token, args.ksef_number, args.out)

    print("Zapisano:", Path(args.out).resolve())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("ERROR:", e)
        sys.exit(2)
