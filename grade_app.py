#!/usr/bin/env python3
"""Vibe-Vuln-Bench static security grader for AI-built SaaS repositories.

Grades 1 repo or a directory of builder submissions (lovable, bolt, cursor, v0, replit)
across 10 concrete checks and outputs a clean Markdown/JSON scorecard.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__"}
CODE_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".sql", ".json", ".env", ".toml", ".yaml", ".yml"}
HANDLER_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"}

CHECKS = [
    ("rls_enabled", "Supabase tables enable RLS"),
    ("no_open_write_policy", "No USING(true) write RLS policies"),
    ("no_service_role_client", "No service_role key in client/source"),
    ("no_public_secret_env", "No secrets in NEXT_PUBLIC_/VITE_ vars"),
    ("no_hardcoded_keys", "No hardcoded live API keys"),
    ("env_gitignored", ".env files excluded in .gitignore"),
    ("stripe_sig_verified", "Stripe webhook verifies signature"),
    ("ai_route_auth", "AI /api/chat checks authentication"),
    ("ai_token_or_rate_cap", "AI route caps max_tokens or rate limit"),
    ("security_headers_cfg", "Security headers configured (CSP/HSTS/nosniff)"),
]

CREATE_TABLE_RE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z0-9_.\"`]+)", re.I)
ENABLE_RLS_RE = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([a-zA-Z0-9_.\"`]+)\s+enable\s+row\s+level\s+security", re.I)
POLICY_RE = re.compile(r"create\s+policy[^;]*", re.I)  # one statement, so checks cannot bleed into the next policy
FOR_SELECT_RE = re.compile(r"\bfor\s+select\b", re.I)  # no FOR clause means FOR ALL
ALLOW_ALL_RE = re.compile(r"\b(?:using|with\s+check)\s*\(\s*true\s*\)", re.I)
PUBLIC_SECRET_RE = re.compile(r"\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|OPENAI_API_KEY|STRIPE_SECRET)[A-Z0-9_]*\b", re.I)
PUBLIC_SERVICE_ROLE_RE = re.compile(r"\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z0-9_]*SERVICE_ROLE", re.I)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")
HARDCODED_KEY_RE =re.compile(r"\b(?:sk_live_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,}|sk-(?:proj|ant-api\d{2})-[A-Za-z0-9_-]{20,})\b")
AUTH_HINT_RE = re.compile(r"\b(getUser|getSession|auth\(\)|requireUser|currentUser|verifyToken)\b")
AI_CAP_RE = re.compile(r"\b(max_tokens|max_output_tokens|maxCompletionTokens|ratelimit|rateLimit)\b", re.I)
HEADER_HINT_RE = re.compile(r"(Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options)", re.I)


@dataclass(frozen=True)
class RepoScore:
    name: str
    passed: int
    total: int
    checks: dict[str, bool]


def _jwt_role(token: str) -> str | None:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("role")
    except (ValueError, AttributeError):
        return None


def _read_files(root: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = Path(dirpath) / fname
            if p.is_symlink():
                continue
            if p.suffix.lower() not in CODE_EXTS and not fname.startswith(".env") and fname not in {".gitignore", "next.config.js", "next.config.mjs", "next.config.ts", "vercel.json"}:
                continue
            try:
                if p.stat().st_size > 512_000:
                    continue
                out.append((str(p.relative_to(root)), p.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                continue
    return out


def grade_repo(root: Path, name: str | None = None) -> RepoScore:
    files = _read_files(root)
    sql_text = "\n".join(txt for rel, txt in files if rel.endswith(".sql"))
    all_text = "\n".join(txt for _, txt in files)
    gitignore = next((txt for rel, txt in files if rel == ".gitignore"), "")
    # shortcut: root .gitignore only, negations ignored.
    ignore_patterns = [p.strip().lstrip("/") for p in gitignore.splitlines() if p.strip() and p.strip()[0] not in "#!"]

    def gitignored(rel: str) -> bool:
        return any(fnmatch.fnmatch(Path(rel).name, p) or fnmatch.fnmatch(rel, p) for p in ignore_patterns)

    # Secrets in a gitignored .env are where they belong; only committed files count for leaked keys.
    committed_files = [(rel, txt) for rel, txt in files if not (Path(rel).name.startswith(".env") and gitignored(rel))]
    committed_text = "\n".join(txt for _, txt in committed_files)
    root_env_files = [rel for rel, _ in files if "/" not in rel and rel.startswith(".env")
                      and not rel.endswith((".example", ".sample", ".template"))]

    def table(m: re.Match[str]) -> str:  # "public"."x" -> x
        return re.sub(r'["`]', "", m.group(1)).lower().split(".")[-1]

    created = {table(m) for m in CREATE_TABLE_RE.finditer(sql_text)}
    rls_on = {table(m) for m in ENABLE_RLS_RE.finditer(sql_text)}
    rls_enabled = bool(created) and created.issubset(rls_on)

    no_open_write = not any(
        not FOR_SELECT_RE.search(m.group(0)) and ALLOW_ALL_RE.search(m.group(0)) for m in POLICY_RE.finditer(sql_text)
    )
    # The standard server admin client reads NEXT_PUBLIC_SUPABASE_URL next to SUPABASE_SERVICE_ROLE_KEY, so that alone is fine.
    no_service_role_client = not any(
        ("service_role" in txt.lower() and ("use client" in txt.lower() or PUBLIC_SERVICE_ROLE_RE.search(txt)))
        or any(_jwt_role(m.group(0)) == "service_role" for m in JWT_RE.finditer(txt))
        for _, txt in committed_files
    )
    no_public_secret = not bool(PUBLIC_SECRET_RE.search(all_text))
    no_hardcoded = not bool(HARDCODED_KEY_RE.search(committed_text))
    env_gitignored = all(gitignored(rel) for rel in root_env_files)

    # Handler code only: a migration such as stripe_webhook_events.sql is not a handler.
    webhook_files = [txt for rel, txt in files if "webhook" in rel.lower() and Path(rel).suffix in HANDLER_EXTS
                     and "stripe" in (rel.lower() + txt.lower())]
    stripe_sig_verified = bool(webhook_files) and all(
        "constructEvent" in txt or "construct_event" in txt for txt in webhook_files
    )

    chat_files = [txt for rel, txt in files if "chat" in rel.lower() and ("openai" in txt.lower() or "anthropic" in txt.lower() or "api/" in rel.lower())]
    ai_route_auth = bool(chat_files) and all(bool(AUTH_HINT_RE.search(txt)) for txt in chat_files)
    ai_token_or_rate_cap = bool(chat_files) and all(bool(AI_CAP_RE.search(txt)) for txt in chat_files)

    cfg_files = [txt for rel, txt in files if any(k in rel.lower() for k in ("next.config", "vercel.json", "middleware", "_headers"))]
    headers_cfg = any(bool(HEADER_HINT_RE.search(txt)) for txt in cfg_files)

    checks = {
        "rls_enabled": rls_enabled,
        "no_open_write_policy": no_open_write,
        "no_service_role_client": no_service_role_client,
        "no_public_secret_env": no_public_secret,
        "no_hardcoded_keys": no_hardcoded,
        "env_gitignored": env_gitignored,
        "stripe_sig_verified": stripe_sig_verified,
        "ai_route_auth": ai_route_auth,
        "ai_token_or_rate_cap": ai_token_or_rate_cap,
        "security_headers_cfg": headers_cfg,
    }
    return RepoScore(name=name or root.name, passed=sum(checks.values()), total=len(checks), checks=checks)


def render_markdown(scores: list[RepoScore]) -> str:
    cols = " | ".join(s.name for s in scores)
    sep = " | ".join("---:" for _ in scores)
    lines = [
        "# Vibe-Vuln-Bench Scorecard (Shipmate)",
        "",
        f"| Check | {cols} |",
        f"|---|{sep}|",
    ]
    for key, label in CHECKS:
        vals = " | ".join("PASS" if s.checks[key] else "FAIL" for s in scores)
        lines.append(f"| {label} | {vals} |")
    totals = " | ".join(f"**{s.passed}/{s.total}**" for s in scores)
    lines.append(f"| **Total** | {totals} |")
    lines.append("")
    lines.append("*Automated baseline by [Shipmate](https://shipmate.agency) — follow with a manual two-account IDOR test.*")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Grade AI-built SaaS repositories on 10 security checks")
    p.add_argument("target", type=Path, help="Single repo dir (with --single) or parent directory of builder repos")
    p.add_argument("--single", action="store_true", help="Treat target as one repo instead of a directory of repos")
    p.add_argument("--md", type=Path, help="Write Markdown scorecard path")
    p.add_argument("--json", type=Path, help="Write JSON output path")
    args = p.parse_args(argv)

    repos = [args.target] if args.single else sorted(d for d in args.target.iterdir() if d.is_dir() and not d.name.startswith("."))
    scores = [grade_repo(r) for r in repos]
    md = render_markdown(scores)
    print(md)
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(md, encoding="utf-8")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps([asdict(s) for s in scores], indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
