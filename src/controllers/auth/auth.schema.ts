// using zod for request validation

import zod from "zod";

export const registerSchema = zod.object({
  email: zod.email(),
  password: zod.string().min(6),
  name: zod.string().min(3),
});

export const loginSchema = zod.object({
  email: zod.email(),
  password: zod.string().min(6),
});
