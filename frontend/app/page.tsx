import { redirect } from "next/navigation";

import { isAuthenticated } from "@/lib/api-server";

export default async function RootPage() {
  redirect((await isAuthenticated()) ? "/dashboard" : "/login");
}
