import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/User.model";
import { hashPassword, verifyPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import { createAccessToken } from "../../lib/token";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}
export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data ",
        error: result.error?.flatten(),
      });
    }

    const { name, email, password } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({
        message: "Email already in use! Please try with a different email",
      });
    }
    //hash password
    const passwordHash = await hashPassword(password);

    // create the new user
    const newlyCreatedUser = await User.create({
      name,
      email: normalizedEmail,
      passwordHash,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    //email varification
    const verifyToken = jwt.sign(
      {
        sub: newlyCreatedUser.id,
      },
      process.env.JWT_ACCESS_SECRET!,
      {
        expiresIn: "1d",
      },
    );
    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newlyCreatedUser.email,
      "Verify your email",
      `
        <p>Please verify your email by clicking this link:</p>
        <p><a href="${verifyUrl}">${verifyUrl}</a></p> 
      `,
    );
    return res.status(201).json({
      message: "User registered",
      user: {
        id: newlyCreatedUser.id,
        email: newlyCreatedUser.email,
        role: newlyCreatedUser.role,
        isEmailVerified: newlyCreatedUser.isEmailVerified,
      },
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server Error",
    });
  }
}

//later on not to return passwordhash, secrets , reset tokens in API reponses

//Verify email handler
export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string | undefined;
  if (!token) {
    return res.status(400).json({ message: "Verification token is missing" });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
    };

    const userId = payload.sub;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({ messsage: "Email already verified" });
    }
    user.isEmailVerified = true;
    await user.save();

    return res.status(200).json({
      message: "Email is now verified. You can login",
    });
  } catch (err) {
    console.log(err);

    return res.status(500).json({
      message: "Invalid or expired verification token",
    });
  }
}

//The loging in handler(handles jwt, bcrypt password hashing, mongo,zod, email verification requirements)
export async function loginHandler(req: Request, res: Response) {
  try {
    // Validate request body
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid input data",
        error: result.error.flatten(),
      });
    }
    // extract the data
    const { email, password } = result.data;

    //normalise email
    const normEmail = email.toLowerCase().trim();

    //find user
    const user = await User.findOne({
      email: normEmail,
    }).select("+passwordHash");

    //if user is not found
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    // email verification
    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify email first",
      });
    }

    //compare passwords
    const isPasswordVerified = await verifyPassword(
      password,
      user.passwordHash,
    );
    if (!isPasswordVerified) {
      return res.status(400).json({
        message: "Invalid credentials",
      });
    }
    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify your email before loging in ",
      });
    }
    //generate access token
    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion,
    );
  } catch (err) {}
}
