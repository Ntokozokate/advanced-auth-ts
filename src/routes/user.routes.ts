import { Request, Response, Router } from "express";

const router = Router();

router.get("/me", (req: Request, res: Response) => {
  const authReq = req as any;
  const authUser = authReq.user;

  res.json({
    user: authUser,
  });
});

export default router;
