"""Control fixture: the same operations, written safely."""

import hashlib
import os
import subprocess

import requests
import yaml

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")


def run_report(name: str) -> None:
    subprocess.run(["generate-report", name], check=True, shell=False)


def digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def load(config: str) -> object:
    import json

    return json.loads(config)


def fetch(url: str) -> str:
    return requests.get(url, timeout=10).text


def parse(document: str) -> object:
    return yaml.safe_load(document)
