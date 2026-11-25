#!/usr/bin/env python3
"""Unit tests for ops/marketing/vibe-vuln-bench/grade_app.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grade_app as ga  # noqa: E402


class TestVibeVulnBench(unittest.TestCase):
    def test_distinguishes_hardened_vs_vulnerable_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vuln = root / "builder_vuln"
            (vuln / "supabase/migrations").mkdir(parents=True)
            (vuln / "app/api/webhooks/stripe").mkdir(parents=True)
            (vuln / "app/api/chat").mkdir(parents=True)
            (vuln / "supabase/migrations/001.sql").write_text("CREATE TABLE public.invoices (id uuid);\n", encoding="utf-8")
            (vuln / ".env").write_text("NEXT_PUBLIC_STRIPE_SECRET=sk_live_1234567890abcdef1234\n", encoding="utf-8")
            (vuln / "app/api/webhooks/stripe/route.ts").write_text("export async function POST(req){ await req.json(); }\n", encoding="utf-8")
            (vuln / "app/api/chat/route.ts").write_text("export async function POST(req){ return openai.chat(); }\n", encoding="utf-8")

            good = root / "builder_hardened"
            (good / "supabase/migrations").mkdir(parents=True)
            (good / "app/api/webhooks/stripe").mkdir(parents=True)
            (good / "app/api/chat").mkdir(parents=True)
            (good / ".gitignore").write_text(".env\n", encoding="utf-8")
            (good / "supabase/migrations/001.sql").write_text(
                "CREATE TABLE public.invoices (id uuid, user_id uuid);\n"
                "ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY p_sel ON public.invoices FOR SELECT USING (auth.uid() = user_id);\n",
                encoding="utf-8",
            )
            (good / "app/api/webhooks/stripe/route.ts").write_text(
                "export async function POST(req){ stripe.webhooks.constructEvent(await req.text(), sig, sec); }\n",
                encoding="utf-8",
            )
            (good / "app/api/chat/route.ts").write_text(
                "export async function POST(req){ const u = await getUser(req); return openai.responses.create({ max_output_tokens: 500 }); }\n",
                encoding="utf-8",
            )
            (good / "next.config.ts").write_text('headers: [{ key: "Content-Security-Policy", value: "default-src \'self\'" }]\n', encoding="utf-8")

            s_vuln = ga.grade_repo(vuln)
            s_good = ga.grade_repo(good)
            self.assertLessEqual(s_vuln.passed, 2)
            self.assertEqual(s_good.passed, 10)
            md = ga.render_markdown([s_vuln, s_good])
            self.assertIn("**10/10**", md)


def checks_for(files: dict[str, str]) -> dict[str, bool]:
    with tempfile.TemporaryDirectory() as td:
        for rel, text in files.items():
            p = Path(td) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return ga.grade_repo(Path(td)).checks


LIVE_KEY = "sk" + "_live_" + "1234567890abcdef1234"


class TestCheckAccuracy(unittest.TestCase):
    def test_rls_quoting_and_if_exists(self) -> None:
        sql = ('create table "public"."workspaces" (id uuid);\ncreate table public.invoices (id uuid);\n'
               "alter table if exists public.workspaces enable row level security;\n"
               'alter table "public"."invoices" enable row level security;\n')
        self.assertTrue(checks_for({"m/001.sql": sql})["rls_enabled"])
        self.assertFalse(checks_for({"m/001.sql": "create table public.invoices (id uuid);\n"})["rls_enabled"])

    def test_env_files_and_gitignore(self) -> None:
        # .env.example is committed, so its keys count; a gitignored .env.local is fine.
        self.assertFalse(checks_for({".env.example": f"STRIPE_SECRET_KEY={LIVE_KEY}\n"})["no_hardcoded_keys"])
        ok = checks_for({".env.local": f"STRIPE_SECRET_KEY={LIVE_KEY}\n", ".env": "A=1\n", ".gitignore": ".env\n.env*.local\n"})
        self.assertTrue(ok["no_hardcoded_keys"])
        self.assertTrue(ok["env_gitignored"])
        # ".env.example" in .gitignore does not ignore .env
        self.assertFalse(checks_for({".env": "A=1\n", ".gitignore": ".env.example\n"})["env_gitignored"])


if __name__ == "__main__":
    unittest.main()
