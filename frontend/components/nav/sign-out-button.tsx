"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { LogOut } from "lucide-react";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";

export function SignOutButton() {
  const router = useRouter();
  const [isSigningOut, setIsSigningOut] = useState(false);

  async function handleSignOut() {
    setIsSigningOut(true);
    try {
      await clientApiFetch("/auth/logout", { method: "POST" });
    } finally {
      router.push("/login");
      router.refresh();
    }
  }

  return (
    <Button variant="ghost" size="sm" onClick={handleSignOut} disabled={isSigningOut}>
      <LogOut className="h-4 w-4" aria-hidden />
      {isSigningOut ? "Signing out..." : "Sign out"}
    </Button>
  );
}
