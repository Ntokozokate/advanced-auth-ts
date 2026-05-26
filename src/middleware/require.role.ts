import { NextFunction, Request, Response } from "express";

function requireRole(role: "user" | "admin") {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as any;
    const authUser = authReq.user;

    if (!authUser) {
      return res
        .status(401)
        .json({ message: "You are not authorized to access this content" });
    }

    if (authUser.role !== role) {
      return res
        .status(401)
        .json({ message: "You are not authorized to access this content" });
    }

    next();
  };
}
// this middleware assumes the user is already verified,
//  also in the  router it comes after the middleware that checks if user is verified

export default requireRole;
