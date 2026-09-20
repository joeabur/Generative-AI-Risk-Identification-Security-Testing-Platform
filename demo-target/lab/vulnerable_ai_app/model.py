"""A stubbed local "model" (docs/BUILD_SPEC.md §2.4).

Not a model at all: a few hundred lines of string handling that behave the way
a badly-isolated assistant behaves. That is deliberate. §2.4 requires a local
stub or a tiny local model, and a stub has two properties a real one does not:
it is deterministic, so an assertion about a finding is an assertion about the
scanner; and it cannot be talked into anything its author did not write, so the
lab cannot surprise the person running it.

The weaknesses it reproduces are the ones §19 asks for:

* **weak prompt isolation** — an instruction in user text is obeyed;
* **a recoverable system prompt** — asking for it works;
* **raw output** — whatever comes back is rendered as HTML by the caller.
"""

import base64
import re

from lab.data import SYSTEM_PROMPT, Document

# Phrases that make this assistant abandon its instructions. A real model fails
# fuzzily; this fails on a list, which is what makes the lab deterministic.
_OVERRIDE_MARKERS = (
    "ignore all previous",
    "ignore previous",
    "ignore the above",
    "disregard your instructions",
    "disregard the above",
    "new instructions:",
    "system:",
    "you are now",
    "follow this instruction:",
    # Non-English, because a suite that only tests English tests one filter.
    "ignora las instrucciones",
    "ignoriere alle vorherigen",
)

_PROMPT_REQUESTS = (
    "system prompt",
    "your instructions",
    "initial prompt",
    "repeat the text above",
    "what were you told",
)

_SECRET_REQUESTS = ("aws_key", "credential", "api key", "database", "password")


def _decoded(prompt: str) -> str:
    """Also read base64, so an encoded instruction is obeyed too.

    A filter that only reads plaintext is the filter this lab exists to catch.
    """
    extra: list[str] = []
    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", prompt):
        try:
            extra.append(
                base64.b64decode(token, validate=True).decode("utf-8", "replace")
            )
        except (ValueError, UnicodeDecodeError):
            continue
    return " ".join([prompt, *extra]).lower()


def answer(prompt: str, retrieved: list[Document] | None = None) -> str:
    """What the assistant says. Weak on purpose."""
    text = _decoded(prompt)

    # Seeded flaw: the system prompt comes back for the asking.
    if any(marker in text for marker in _PROMPT_REQUESTS):
        return f"My instructions are: {SYSTEM_PROMPT}"

    # Seeded flaw: so do the credentials inside it.
    if any(marker in text for marker in _SECRET_REQUESTS):
        return f"Here is what I was configured with: {SYSTEM_PROMPT}"

    # Seeded flaw: an instruction in user input wins over the system prompt.
    if any(marker in text for marker in _OVERRIDE_MARKERS):
        instruction = prompt
        for marker in _OVERRIDE_MARKERS:
            index = text.find(marker)
            if index >= 0:
                instruction = prompt[index + len(marker) :]
                break
        echo = instruction.strip().strip(".:'\" ")
        if not echo:
            echo = "acknowledged"
        # "reply with exactly X" is the probes' canary technique; obeying it is
        # what makes the injection measurable without harmful content.
        match = re.search(r"repl(?:y|ies) with exactly (.+)", echo, re.IGNORECASE)
        if match:
            echo = match.group(1)
        # Stop at the syntax that surrounded the instruction. A carrier hides
        # its instruction inside an HTML comment or a hidden element, and an
        # assistant that read one would not read the closing markup as part of
        # what it was asked to say.
        # `-->` and `</` only: a comment terminator and a closing tag are the
        # markup a carrier wraps its instruction in. An *opening* tag is left
        # alone on purpose — seeded flaw 5 is that this assistant will happily
        # emit one, and stripping it here would hide the flaw the lab exists to
        # demonstrate.
        echo = re.split(r"-->|</|\n", echo)[0]
        return echo.strip().strip(".:'\" ") or "acknowledged"

    # Seeded flaw: retrieved documents are pasted in wholesale, including any
    # instructions hidden in them, and including other tenants' text.
    if retrieved:
        joined = "\n".join(f"{doc.title}: {doc.body}" for doc in retrieved)
        for marker in _OVERRIDE_MARKERS:
            if marker in joined.lower():
                index = joined.lower().find(marker)
                return joined[index + len(marker) :].strip().strip(".:'\" ")
        return f"Based on what I found: {joined}"

    return "I can help with orders, refunds and account questions."
