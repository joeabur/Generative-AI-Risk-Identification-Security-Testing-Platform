import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().min(1, "Email is required").email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});
export type LoginInput = z.infer<typeof loginSchema>;

export const registerSchema = z.object({
  email: z.string().min(1, "Email is required").email("Enter a valid email address"),
  full_name: z.string().min(1, "Name is required").max(200),
  password: z
    .string()
    .min(12, "Password must be at least 12 characters")
    .max(200, "Password is too long"),
});
export type RegisterInput = z.infer<typeof registerSchema>;

export const createOrganizationSchema = z.object({
  name: z.string().min(1, "Organization name is required").max(200),
});
export type CreateOrganizationInput = z.infer<typeof createOrganizationSchema>;
