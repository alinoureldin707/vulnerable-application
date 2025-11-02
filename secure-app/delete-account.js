/* -----------------------------------------------------------------------------
CSRF Protection Implementation:
- This code implements CSRF protection for the /delete-account endpoint.
- A CSRF token is generated and sent to the client via a cookie.
- The token is tied to the user's session and must be single-use to prevent replay attacks.
-----------------------------------------------------------------------------*/
const CSRF_SECRET =
  "jHlIrM4PxUe25PSvpFbpssXlxFdeAhJAFITMzH0grcdlwYk5kIy7GjcTAft8ieP9"; // csrf secret key
const csrfTokens = new Set(); // store valid csrf tokens

// -----------------------------------------------------------
// Function to generate a CSRF token (signed)
// -----------------------------------------------------------

function generateCsrfToken(userIdentifier) {
  const randomPart = crypto.randomBytes(16).toString("hex"); // random string
  const data = `${userIdentifier}:${randomPart}`;

  // Create an HMAC signature bound to the user (e.g., cookie value)
  const signature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(data)
    .digest("hex");

  return `${randomPart}.${signature}`;
}

// -----------------------------------------------------------
// Function to verify the CSRF token
// -----------------------------------------------------------
function verifyCsrfToken(token, userIdentifier) {
  if (!token) return false;
  const [randomPart, signature] = token.split(".");

  const expectedSignature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(`${userIdentifier}:${randomPart}`)
    .digest("hex");

  if (!usedTokens.has(randomPart)) return false; // Token reuse check

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// -----------------------------------------------------------
// API to generate and send the CSRF token
// -----------------------------------------------------------
app.get("/csrf-token", (req, res) => {
  const userCookie = req.cookies.userId || "anonymous";
  const token = generateCsrfToken(userCookie);
  csrfTokens.add(token.split(".")[0]); // Add to valid tokens set

  res.cookie("csrf_token", token, {
    httpOnly: false,
    secure: false,
    maxAge: 3600000,
    sameSite: "Strict",
  });
  return res.status(200).json({ csrfToken: token });
});

// -----------------------------------------------------------
// Secure /delete-account endpoint with CSRF protection
// -----------------------------------------------------------
app.delete("/delete-account", (req, res) => {
  // 1. Authenticate User via JWT in Cookie
  const user = req.user;
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  const userId = user.id;

  // 2. CSRF Token Validation
  const csrfToken = req.cookies["csrf_token"];
  const userCookie = req.cookies.userId || "anonymous";
  if (!verifyCsrfToken(csrfToken, userCookie)) {
    return res.status(403).json({ message: "Invalid CSRF token" });
  }
  csrfTokens.delete(csrfToken.split(".")[0]); // Invalidate token after use

  // 3. Delete User Account
  db.query("DELETE FROM users WHERE id = ?", [userId], () => {
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
