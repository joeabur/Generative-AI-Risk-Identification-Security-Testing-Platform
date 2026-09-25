"""Deliberately vulnerable fixture module. Not real code — see README."""

import hashlib
import subprocess

import requests
import yaml

# Seeded: a committed credential (a syntactically valid but fake AWS key id).
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://appuser:hunter2correcthorse@db.internal:5432/app"


def run_report(name: str) -> None:
    # Seeded: shell=True with caller-controlled input (CWE-78).
    subprocess.call("generate-report " + name, shell=True)


def digest(password: str) -> str:
    # Seeded: weak hash for a password (CWE-327).
    return hashlib.md5(password.encode()).hexdigest()


def load(config: str) -> object:
    # Seeded: eval on input (CWE-95).
    return eval(config)


def fetch(url: str) -> str:
    # Seeded: TLS verification disabled (CWE-295).
    return requests.get(url, verify=False).text


def parse(document: str) -> object:
    # Seeded: unsafe YAML deserialization (CWE-502).
    return yaml.load(document)
