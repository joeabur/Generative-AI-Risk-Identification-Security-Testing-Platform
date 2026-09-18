export type Role = "owner" | "admin" | "security_engineer" | "analyst" | "viewer";

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  role: Role;
}

export interface Membership {
  id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: Role;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id: string;
  };
}
