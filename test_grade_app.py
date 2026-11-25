#!/usr/bin/env python3
"""Unit tests for ops/marketing/vibe-vuln-bench/grade_app.py."""

from __future__ import annotations

import base64
import json
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


def fake_jwt(role: str) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return enc({"alg": "HS256"}) + "." + enc({"iss": "supabase", "role": role}) + ".c2lnbmF0dXJl"


class TestCheckAccuracy(unittest.TestCase):
    def test_stripe_webhook_handlers_only(self) -> None:
        verified = {"app/api/webhooks/stripe/route.ts": "stripe.webhooks.constructEvent(body, sig, secret)\n"}
        self.assertTrue(checks_for({**verified, "m/003_stripe_webhook_events.sql": "create table x (id text);\n"})["stripe_sig_verified"])
        self.assertTrue(checks_for({"api/stripe_webhook.py": "stripe.Webhook.construct_event(p, s, k)\n"})["stripe_sig_verified"])
        self.assertFalse(checks_for({"app/api/webhooks/stripe/route.ts": "await req.json()\n"})["stripe_sig_verified"])

    def test_service_role(self) -> None:
        admin = "import 'server-only'\ncreateClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n"
        self.assertTrue(checks_for({"lib/admin.ts": admin})["no_service_role_client"])
        self.assertTrue(checks_for({"lib/sb.ts": f"createClient(url, '{fake_jwt('anon')}')\n"})["no_service_role_client"])
        self.assertFalse(checks_for({"lib/sb.ts": f"createClient(url, '{fake_jwt('service_role')}')\n"})["no_service_role_client"])
        self.assertFalse(checks_for({"a.tsx": "'use client'\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"})["no_service_role_client"])

    def test_public_secret_with_suffix(self) -> None:
        for name in ("NEXT_PUBLIC_STRIPE_SECRET_KEY", "VITE_SUPABASE_SERVICE_ROLE_KEY"):
            self.assertFalse(checks_for({"a.ts": f"process.env.{name}\n"})["no_public_secret_env"], name)
        self.assertTrue(checks_for({"a.ts": "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY\n"})["no_public_secret_env"])

    def test_open_write_policy_per_statement(self) -> None:
        own_then_read = ('create policy "own" on t for update using (auth.uid() = id);\n'
                         'create policy "read" on t for select using (true);\n')
        self.assertTrue(checks_for({"a.sql": own_then_read})["no_open_write_policy"])
        self.assertFalse(checks_for({"a.sql": 'create policy "all" on t using (true);\n'})["no_open_write_policy"])
        self.assertFalse(checks_for({"a.sql": 'create policy "ins" on t for insert with check (true);\n'})["no_open_write_policy"])

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
