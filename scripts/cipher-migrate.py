#!/usr/bin/env python3
"""
Migrates ${SECRET_VAR} references in config-repo YAMLs to Spring Cloud Config
'{cipher}HEX' format.

Uses the exact Spring Security Crypto algorithm:
  AES/CBC/PKCS5Padding + PBKDF2WithHmacSHA1(key, salt=0xDEADBEEF, 1024 iter, 256-bit)

Usage:
  export ENCRYPT_KEY="your_encrypt_key_from_github_secrets"
  python3 scripts/cipher-migrate.py \
      --secrets scripts/secrets.dev.env \
      --repo    path/to/config-repos \
      [--dry-run]

  # Verify a single value round-trips correctly:
  python3 scripts/cipher-migrate.py --test "hello" --verify-cipher "HEX..."
"""

import argparse
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Fixed salt used by Spring Cloud Config's Encryptors.text(key, "deadbeef")
_SPRING_SALT = bytes.fromhex("deadbeef")

# -------------------------------------------------------------------
# Core crypto — matches Spring Security AesBytesEncryptor (CBC)
# -------------------------------------------------------------------

def _derive_key(encrypt_key: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,          # 256-bit AES key
        salt=_SPRING_SALT,
        iterations=1024,
    )
    return kdf.derive(encrypt_key.encode("utf-8"))


def spring_encrypt(plaintext: str, encrypt_key: str) -> str:
    """Return hex(random_iv + AES_CBC_ciphertext) — matches Spring /encrypt output."""
    aes_key = _derive_key(encrypt_key)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    return (iv + enc.update(padded) + enc.finalize()).hex()


def spring_decrypt(cipher_hex: str, encrypt_key: str) -> str:
    """Inverse of spring_encrypt — for verification."""
    aes_key = _derive_key(encrypt_key)
    raw = bytes.fromhex(cipher_hex)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")

# -------------------------------------------------------------------
# Variables that must become {cipher} — everything else stays ${VAR}
# -------------------------------------------------------------------

CIPHER_VARS: set[str] = {
    # Database
    "DB_PASSWORD", "DATABASE_PASSWORD",
    # MongoDB
    "MONGODB_URI", "MONGO_PASSWORD", "SPRING_DATA_MONGODB_URI",
    # Redis
    "REDIS_PASSWORD",
    # Elasticsearch
    "ELASTICSEARCH_PASSWORD",
    # Milvus
    "MILVUS_PASSWORD",
    # MinIO
    "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY",
    # FusionAuth
    "FUSIONAUTH_API_KEY", "FUSIONAUTH_CLIENT_SECRET",
    # OAuth2 client secrets
    "GH_OAUTH2_CLIENT_SECRET", "GOOGLE_OAUTH2_CLIENT_SECRET",
    # JWT
    "JWT_KEYSTORE_PASSWORD",
    # Stripe
    "STRIPE_SECRET_KEY", "STRIPE_API_KEY",
    "STRIPE_WEBHOOK_SECRET", "STRIPE_TEST_SECRET_KEY", "STRIPE_TEST_WEBHOOK_SECRET",
    # PayPal
    "PAYPAL_CLIENT_SECRET", "PAYPAL_WEBHOOK_SECRET",
    # Paystack
    "PAYSTACK_SECRET_KEY", "PAYSTACK_WEBHOOK_SECRET",
    # Twilio (core)
    "TWILIO_AUTH_TOKEN",
    # Monitoring / infra
    "GRAFANA_API_KEY", "MEILISEARCH_API_KEY", "SVIX_API_KEY",
    # Firebase / FCM
    "FCM_SERVER_KEY", "FIREBASE_PRIVATE_KEY",
    # Flutterwave
    "FLUTTERWAVE_SECRET_KEY", "FLUTTERWAVE_ENCRYPTION_KEY", "FLUTTERWAVE_WEBHOOK_SECRET",
    # Yellowcard
    "YELLOWCARD_API_KEY", "YELLOWCARD_WEBHOOK_SECRET",
    # Other
    "VAULT_TOKEN", "PAYMENT_ENCRYPTION_KEY",
    "SMTP_PASSWORD", "SPRING_MAIL_PASSWORD",
    # Notification service — all provider secrets
    "NOTIFICATION_EMAIL_SMTP_PASSWORD",
    "NOTIFICATION_EMAIL_AMAZON_SES_ACCESS_KEY", "NOTIFICATION_EMAIL_AMAZON_SES_SECRET_KEY",
    "NOTIFICATION_EMAIL_MAILGUN_API_KEY",
    "NOTIFICATION_EMAIL_MAILJET_API_KEY", "NOTIFICATION_EMAIL_MAILJET_SECRET_KEY",
    "NOTIFICATION_EMAIL_SENDGRID_API_KEY",
    "NOTIFICATION_EMAIL_TWILIO_API_KEY",
    "NOTIFICATION_CHAT_DISCORD_BOT_TOKEN",
    "NOTIFICATION_CHAT_SLACK_BOT_TOKEN", "NOTIFICATION_CHAT_SLACK_SIGNING_SECRET",
    "NOTIFICATION_CHAT_TELEGRAM_BOT_TOKEN",
    "NOTIFICATION_CHAT_MICROSOFT_TEAMS_APP_PASSWORD",
    "NOTIFICATION_SMS_AMAZON_SNS_ACCESS_KEY", "NOTIFICATION_SMS_AMAZON_SNS_SECRET_KEY",
    "NOTIFICATION_SMS_SINCH_API_KEY", "NOTIFICATION_SMS_SINCH_SECRET",
    "NOTIFICATION_SMS_TWILIO_AUTH_TOKEN",
    "NOTIFICATION_SOCIAL_WHATSAPP_BUSINESS_ACCESS_TOKEN",
    "NOTIFICATION_SOCIAL_WHATSAPP_TWILIO_AUTH_TOKEN",
    "NOTIFICATION_VOICE_TWILIO_AUTH_TOKEN",
}

SKIP_PLACEHOLDER = {"__CHANGE_ME__", "__TODO__", ""}

# -------------------------------------------------------------------
# YAML processing
# -------------------------------------------------------------------

_VAR_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::[^}]*)?\}")


def process_yaml(content: str, secrets: dict[str, str], encrypt_key: str) -> tuple[str, list[str]]:
    changes: list[str] = []

    def replace(m: re.Match) -> str:
        var = m.group(1)
        if var not in CIPHER_VARS:
            return m.group(0)                       # keep ${VAR:default}
        val = secrets.get(var, "")
        if val in SKIP_PLACEHOLDER:
            return m.group(0)                       # no value — leave placeholder
        cipher_hex = spring_encrypt(val, encrypt_key)
        changes.append(var)
        return f"'{{cipher}}{cipher_hex}'"

    return _VAR_RE.sub(replace, content), changes

# -------------------------------------------------------------------
# Secrets file loader  (KEY=VALUE, # comments, blank lines ignored)
# -------------------------------------------------------------------

def load_secrets(path: str) -> dict[str, str]:
    secrets: dict[str, str] = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            secrets[key.strip()] = value.strip()
    return secrets

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Migrate ${SECRET} → '{cipher}HEX' in config-repo YAMLs")
    ap.add_argument("--secrets", help="Path to secrets.env file (KEY=VALUE)")
    ap.add_argument("--repo",    default=".", help="Path to config-repo root (default: .)")
    ap.add_argument("--dry-run", action="store_true", help="Print changes without writing files")
    ap.add_argument("--test",    metavar="PLAINTEXT", help="Encrypt a single value and print, then exit")
    ap.add_argument("--verify",  metavar="CIPHER_HEX", help="Decrypt a {cipher} hex value and print, then exit")
    args = ap.parse_args()

    encrypt_key = os.environ.get("ENCRYPT_KEY", "").strip()
    if not encrypt_key:
        sys.exit("ERROR: set ENCRYPT_KEY environment variable first")

    # Quick-test mode
    if args.test:
        hex_val = spring_encrypt(args.test, encrypt_key)
        print(f"'{{cipher}}{hex_val}'")
        back = spring_decrypt(hex_val, encrypt_key)
        print(f"verify decrypt → {back!r}  {'✓' if back == args.test else '✗ MISMATCH'}")
        return

    if args.verify:
        print(spring_decrypt(args.verify, encrypt_key))
        return

    if not args.secrets:
        ap.error("--secrets is required (unless --test / --verify)")

    secrets = load_secrets(args.secrets)
    print(f"Loaded {len(secrets)} secrets\n")

    repo = Path(args.repo)
    total = 0

    for yml in sorted(repo.rglob("*.yml")):
        original = yml.read_text()
        updated, changes = process_yaml(original, secrets, encrypt_key)
        if not changes:
            continue
        total += len(changes)
        rel = yml.relative_to(repo)
        print(f"{rel}")
        for v in changes:
            print(f"  ✓  {v}")
        if not args.dry_run:
            yml.write_text(updated)

    if total == 0:
        print("Nothing to change — all cipher vars already encrypted or no values provided.")
    else:
        print(f"\n{'[DRY-RUN] ' if args.dry_run else ''}Encrypted {total} variable(s) across config-repo.")
        if not args.dry_run:
            print("\nNext steps:")
            print("  1. git diff  — review the changes")
            print("  2. git add -A && git commit -m 'security: migrate secrets to {cipher} encryption'")
            print("  3. Delete the 30+ stale secrets from config-service GitHub env (keep only ENCRYPT_KEY + infra)")


if __name__ == "__main__":
    main()
