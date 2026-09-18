import type { Metadata } from "next";

import { CreateOrganizationForm } from "@/components/organizations/create-organization-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata: Metadata = { title: "New organization — Aegis AI Security" };

export default function NewOrganizationPage() {
  return (
    <div className="mx-auto max-w-md">
      <Card>
        <CardHeader>
          <CardTitle>Create an organization</CardTitle>
          <CardDescription>
            You&apos;ll become its Owner, with the sole ability to grant testing authorization for
            assets registered under it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CreateOrganizationForm />
        </CardContent>
      </Card>
    </div>
  );
}
