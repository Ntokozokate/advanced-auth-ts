import { Request, Response, Router } from "express";
import requireAuth from "../middleware/require.auth";
import requireRole from "../middleware/require.role";
import { User } from "../models/User.model";

const router = Router();

router.get(
  "/user",
  requireAuth,
  requireRole("admin"),
  async (req: Request, res: Response) => {
    try {
      const users = await User.find(
        {},
        {
          email: 1,
          role: 1,
          isEmailVerified: 1,
          createdAt: 1,
        },
      ).sort({ createdAt: -1 });

      const result = users.map((u) => ({
        id: u.id,
        email: u.email,
        role: u.role,
        isEmailVerified: u.isEmailVerified,
        createdAt: u.createdAt,
      }));

      return res.json({ users: result });
    } catch (err) {
      console.log(err);
      return res.status(500).json({
        message: "Something went wrong",
      });
    }
  },
);

export default router;
