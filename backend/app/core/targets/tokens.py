"""Pre-flight token estimation.

docs/BUILD_SPEC.md §6.2: "Token budgets use the provider's reported usage
when available and a tokenizer estimate otherwise; document that the estimate
is an estimate."

This is **not** a tokenizer. It is a ~4-characters-per-token heuristic, which
is roughly right for English prose with a real BPE tokenizer and can be off
by a wide margin for code, non-Latin scripts, or long unbroken strings. It
exists only so a budget check has *some* pre-flight number; the moment a
provider reports real usage, `BudgetTracker.reconcile()` replaces the
estimate with the truth. A real tokenizer (e.g. tiktoken) is tracked in
docs/roadmap.md rather than pretended at here.
"""

_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, len(text) // _CHARS_PER_TOKEN)
