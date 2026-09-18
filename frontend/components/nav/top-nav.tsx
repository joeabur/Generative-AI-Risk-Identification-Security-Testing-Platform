import Link from "next/link";
import { ShieldCheck } from "lucide-react";

import { SignOutButton } from "@/components/nav/sign-out-button";
import type { User } from "@/lib/types";

export function TopNav({ user }: { user: User }) {
  return (
    <header className="border-b border-border bg-card">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4">
        <Link href="/dashboard" className="flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-primary" aria-hidden />
          <span className="font-semibold tracking-tight">Aegis AI Security</span>
        </Link>
        <div className="flex items-center gap-4">
          <span className="text-sm text-muted-foreground">{user.full_name}</span>
          <SignOutButton />
        </div>
      </div>
    </header>
  );
}
