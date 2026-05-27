import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/User.model";
import { hashPassword, verifyPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !clientSecret) {
    throw new Error("Google client id and secret both are missing");
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
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

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    // access token can be put un the response but the refresh toke has to be stored in the cookies header
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: isProd,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Logged in successfully",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (err) {
    console.log(err);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function refreshTokenHandler(req: Request, res: Response) {
  try {
    const refreshToken = req.cookies.refreshToken as string | undefined;

    if (!refreshToken) {
      return res.status(401).json({
        message: "Refresh token missing",
      });
    }
    //verify the token and get payload
    const payload = verifyRefreshToken(refreshToken);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(401).json({
        message: "User not found",
      });
    }
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        message: "Refresh token Invalid",
      });
    }
    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion,
    );
    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: isProd,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: newAccessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (err) {
    console.log(err);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  try {
    //check if the refresh token even exists nd if there is no token they are technically already logged out

    const refreshToken = req.cookies.refreshToken as string | undefined;

    if (!refreshToken) {
      return res.status(200).json({
        message: "User logged out",
      });
    }

    res.clearCookie("refreshToken", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    });

    return res.status(200).json({
      message: "Logged out successfully",
    });
  } catch (err) {
    console.error("Logout error", err);

    return res.status(500).json({
      message: "Internal Server Error ",
    });
  }
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  try {
    const { email } = req.body as { email?: string };

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });

    // Always return same message
    // prevents email enumeration attacks
    if (!user) {
      return res.status(200).json({
        message:
          "If an account with this email exists, a reset link has been sent",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    //always hash this token before saving it to db
    const hashedToken = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    //store the token in db
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);

    await user.save();

    //create frontend url that the user will use to navigate to reset page

    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      "Reset your password",
      `
  <h4>Password Reset Request </h4>
    <p>Click on the link below to reset your password </p>
    <p><a href="${resetUrl}">${resetUrl}</a></p>
    <p>This link is highly sensitive and will expire in 15 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
  `,
    );

    return res
      .status(200)
      .json({ message: "If an account exists, a reset link has been sent" });
  } catch (err) {
    console.error("Reset password error", err);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}
// Flow:
// User clicks email link
// Frontend sends token + new password
// Then I:
// hashe token
// find matching user in db
// checks expiry
// update password
// clear reset fields

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token, newPassword } = req.body as {
    token?: string;
    newPassword?: string;
  };

  if (!token) {
    return res.status(400).json({
      message: "Reset token is missing",
    });
  }

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({
      message: "Password must atleast be 6 char",
    });
  }

  try {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    //find the user that will match the token and that is not expired

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired reset token",
      });
    }
    //updte the password info
    const newHashedPassword = await hashPassword(newPassword);

    user.passwordHash = newHashedPassword;

    //clear reset fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    user.tokenVersion = user.tokenVersion + 1;

    await user.save();

    return res.status(200).json({
      message: "Password reset successful",
    });
  } catch (err) {
    console.error("Reset password error", err);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}
export async function googleAuthStartHandler(_req: Request, res: Response) {
  try {
    const client = getGoogleClient();

    const url = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });

    return res.redirect(url);
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  const code = req.query.code as string | undefined;

  if (!code) {
    return res.status(400).json({
      message: "Missing code in callback",
    });
  }

  try {
    const client = getGoogleClient();

    const { tokens } = await client.getToken(code);

    if (!tokens.id_token) {
      return res.status(400).json({
        message: "No googles id_token is present",
      });
    }

    //verify id tokena and read the user info from it
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });

    const payload = ticket.getPayload();

    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    if (!email || !emailVerified) {
      return res.status(400).json({
        message: "Google email account is not verified",
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const passwordHash = await hashPassword(randomPassword);

      user = await User.create({
        email: normalizedEmail,
        passwordHash,
        role: "user",
        isEmailVerified: true,
        twoFactorEnabled: false,
      });
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }

    const accessToken = createAccessToken(
      user.id,
      user.role as "user" | "admin",
      user.tokenVersion,
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      message: "Google login successfully",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}
