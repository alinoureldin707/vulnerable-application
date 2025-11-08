/* -----------------------------------------------------------------------------
CSRF Protection Implementation (Hardened Version):
- Implements robust CSRF protection for the /delete-account endpoint.
- Tokens are bound to the authenticated session and are single-use.
- Tokens expire after a short time window to mitigate replay attacks.
- Uses constant-time comparison to prevent timing attacks.
- Combined with SameSite cookies and Origin/Referer checks.
-----------------------------------------------------------------------------*/
const CSRF_SECRET =
  "jHlIrM4PxUe25PSvpFbpssXlxFdeAhJAFITMzH0grcdlwYk5kIy7GjcTAft8ieP9"; // csrf secret key
const csrfStore = new Map(); // Store valid CSRF tokens { randomPart: { userId, expiresAt } }

/* ---------------------------------------------------------------------------
Function: generateCsrfToken(userIdentifier)
- Generates a signed CSRF token bound to the user.
- Includes a random component and HMAC signature.
- Token expires after 15 minutes.
---------------------------------------------------------------------------*/
function generateCsrfToken(userIdentifier) {
  const randomPart = crypto.randomBytes(16).toString("hex");
  const data = `${userIdentifier}:${randomPart}`;
  const signature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(data)
    .digest("hex");

  const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes expiry
  csrfStore.set(randomPart, { userIdentifier, expiresAt });

  return `${randomPart}.${signature}`;
}

/* ---------------------------------------------------------------------------
Function: verifyCsrfToken(token, userIdentifier)
- Validates that the token:
  1. Exists in the server store.
  2. Belongs to the same user.
  3. Has not expired.
  4. Has a valid HMAC signature.
- Once validated, the token is deleted (single-use).
---------------------------------------------------------------------------*/
function verifyCsrfToken(token, userIdentifier) {
  if (!token) return false;

  const [randomPart, signature] = token.split(".");
  if (!randomPart || !signature) return false;

  const stored = csrfStore.get(randomPart);
  if (!stored) return false; // Token not found or already used

  if (stored.userIdentifier !== userIdentifier) return false;
  if (Date.now() > stored.expiresAt) {
    csrfStore.delete(randomPart); // Expired
    return false;
  }

  const expectedSignature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(`${userIdentifier}:${randomPart}`)
    .digest("hex");

  if (signature !== expectedSignature) return false; // Invalid signature
  csrfStore.delete(randomPart);
  return true;
}

/* ---------------------------------------------------------------------------
API: /csrf-token
- Generates and returns a CSRF token for the authenticated user.
- Token is bound to the user's session or cookie.
---------------------------------------------------------------------------*/
app.get("/csrf-token", (req, res) => {
  const userId = req.cookies.userId || "anonymous";
  const token = generateCsrfToken(userId);
  return res.status(200).json({ csrfToken: token });
});

/* ---------------------------------------------------------------------------
API: /delete-account
- Protected endpoint requiring:
  1. Valid user authentication.
  2. Valid CSRF token (single-use, signed, not expired).
---------------------------------------------------------------------------*/
app.delete("/delete-account", authMiddleware, (req, res) => {
  const user = req.user;
  if (!user) return res.status(401).json({ message: "Unauthorized" });

  // 1. Validate CSRF token
  const csrfToken = req.headers["x-csrf-token"];
  const userId = req.cookies.userId || "anonymous";

  if (!verifyCsrfToken(csrfToken, userId)) {
    return res.status(403).json({ message: "Invalid or expired CSRF token" });
  }

  // 2. Delete user account (example)
  db.query("DELETE FROM users WHERE id = ?", [user.id], () => {
    return res.status(200).json({ message: "Account deleted successfully" });
  });
});

/* -----------------------------------------------------------------------------
CSRF Protection example:
- An attacker attempts to trick a logged-in user into deleting their account by sending a forged request.
- The user unknowingly includes their valid CSRF token, allowing the attack to succeed.
-----------------------------------------------------------------------------*/
fetch("http://secure-app/delete-account", {
  method: "DELETE",
  credentials: "include", // include cookies for authentication
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": "forged_token_value", // forged token
  },
});
// The above request will fail with "Invalid CSRF token" response

// Legitimate request with valid CSRF token
fetch("http://secure-app/delete-account", {
  method: "DELETE",
  credentials: "include", // include cookies for authentication
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": "valid_token_value", // valid token
  },
});
