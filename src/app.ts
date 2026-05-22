// not entry point
// Will keep all the Express application logic
//create the expressa app, cookie parser etc

import express from "express";
import cookieParser from "cookie-parser";

const app = express();

app.use(express.json());
app.use(cookieParser());
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

export default app;
