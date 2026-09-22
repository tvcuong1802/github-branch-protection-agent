"""What THIS agent's output must not be used for, and how it reads a request.

Kept in its own module so the wording lives beside the agent it describes, while the
MECHANISM stays byte-identical fleet-wide in ``disclaimer.py`` and ``input_intake.py``.
A generic "AI-generated draft" is true of every template here and tells a reader nothing
they can act on; this names the decisions the output must not stand in for.
"""

from __future__ import annotations

SCOPE_EN = "Reference only: a record of a GitHub branch-protection change and what the instruction asked for. It is not a security review, not an approval of the resulting policy, and not a substitute for your repository owner's judgement."

SCOPE_JA = (
    " "
    "参考情報です。GitHub ブランチ保護設定の変更内容と指示の記録であり、セキュリティレビューでも、設定内容の承認でも、リポジトリ管理者の判断に代わるものでもありません。"
)


# Names that stay in Latin script inside a Japanese answer -- they are names, not
# English prose, and a language check that counts them gets this agent wrong.
LANGUAGE_POLICY: dict[str, object] = {
    "identifiers": ("GitHub",),
}


# What the intake call reads out of a free-form request. No `fields` are declared:
# this agent's own extractors already recover what it needs, and a second extractor
# would be a second source of truth. What the call adds is the language of the answer
# -- a request typed in romanised Japanese is entirely Latin, and reading the
# characters gets that reader wrong.
INTAKE_POLICY: dict[str, object] = {
    "languages": ("en", "ja"),
    "default_language": "en",
    "fields": {},
    "capabilities": (
        "Configure a GitHub branch protection rule from a plain-language instruction",
        "Say which protections the instruction sets and which it leaves untouched",
        "Flag a change that would weaken an existing protection",
    ),
    "examples": (
        {
            "message": "Require two approving reviews on main in the payments repo.",
            "expect": {"language": "en", "fields": {}, "fits": "yes", "suggestion": None},
        },
        {
            "message": "payments リポジトリの main に承認レビュー2件を必須にしてください。",
            "expect": {"language": "ja", "fields": {}, "fits": "yes", "suggestion": None},
        },
        {
            "message": "Merge this pull request for me.",
            "expect": {"language": "en", "fields": {}, "fits": "no", "suggestion": 1},
        },
    ),
}

# Re-exported so every call site reads `from src.services.agent_scope import
# resolve_answer_language` -- the wording above is per agent, the mechanism is not, and it
# lives in language_decision.py where one patch fixes every repo.
from src.services.language_decision import (  # noqa: E402
    language_instruction,
    resolve_answer_language,
)

__all__ = [
    "INTAKE_POLICY",
    "LANGUAGE_POLICY",
    "SCOPE_EN",
    "SCOPE_JA",
    "language_instruction",
    "resolve_answer_language",
]
