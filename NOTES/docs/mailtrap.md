# EXTERNAL SERVICE CONFIGURATION(Mailtrap)

SETUP and STEPS

1 Register and set up

- Go to mailtrap.io , create account and register (you might wanna add a domain to keep things neat if asked to )
- On home page, go to sandboxes, select My Sandboxes. Copy credentials(host, port, username, password). Paste these in your env file for future use
  Example -
  SMTP_HOST=sandbox.smtp.mailtrap.io
  SMTP_PORT=2525
  SMTP_USER=5d43ee5**\*\*\*\***
  SMTP_PASS=3c9f77**\*\***
  EMAIL_FROM="Adv Auth App<no-reply@advauthapp.com>

**Dependencies:**

- IInstall the mailer and its TypeScript definitions

```bash
  npm i nodemailer
  npm i --save-dev @types/nodemailer
```

2 (Email Service Utility)lib/email.ts
**Core Responsibilities:**

- This file acts as an abstrction layer between the auth controller logic and Mailtrap
- handles asyncronous delivery system-generated emails
- Main technical operations are :
  1. Environment validation, (check essential SMTP creds)
  2. Transport configuration (initializes nodemailer using the host , port and the authentication details)
  3. Formats application data into structured email payloads understood by Nodemailer.
  4. Asynchronous Delivery: Handles the network-heavy task of sending mail without blocking the main event loop.

3. Implementation Flow
   **Authentication flow**

- Define the Function: Create the sendEmail helper .
- Generate a Secure Token: In the controller, sign a JWT containing the user's unique ID.
- Construct the Verification URL: Build a link pointing to your backend's verification endpoint (e.g., http://localhost:3000/auth/verify-email?token=...).
  Dispatch: Call sendEmail with the user's address and the HTML template containing the verification link.
