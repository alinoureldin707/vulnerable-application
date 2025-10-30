const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const db = require("./db"); // Assume this is a configured database connection
const JWT_SECRET = "secretkey";
const app = express();
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");
const FileType = require("file-type"); // npm install file-type

app.use(bodyParser.json());
app.use(cookieParser());

// 1.1. SQL Injection Vulnerability Fix
// This code has been fixed to prevent SQL injection risks.
app.post("/login", (req, res) => {
  // 1. Get Input
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Missing credentials" });

  // 2. Prepare the SQL Query
  // FIX: Use parameterized queries to prevent SQL injection
  // User inputs are passed as parameters rather than being directly concatenated.
  // It treats user inputs as string literals, preventing execution of malicious SQL code.
  const sqlQuery = "SELECT * FROM users WHERE email = ? AND password = ?";

  let user = null;

  // 3. Execute the Query
  db.query(sqlQuery, [email, password], (_, results) => {
    if (results.length > 0) user = results[0];
  });

  // 4. Handle Result (Failure)
  if (!user)
    return res
      .status(401)
      .json({ status: "FAILURE", message: "Invalid credentials" });

  // 5. Success & JWT Generation
  const payload = { userId: user.id, role: user.role };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

  // 6. Set HTTP-ONLY Cookie
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: false,
    maxAge: 3600000,
    sameSite: "Lax",
  });

  // 7. Return Success
  return res.status(200).json({
    status: "SUCCESS",
    message: `Welcome, ${user.email}!`,
    role: user.role,
  });
});

// 1.2. SQL Injection Vulnerability Fix
// This code has been fixed to prevent SQL injection risks.
app.get("/search-advertisements", (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ message: "Missing search query" });

  // FIX: Use parameterized queries to prevent SQL injection
  const sqlQuery = "SELECT * FROM advertisements WHERE title LIKE ?";

  // Execute the Query with parameterized input
  db.query(sqlQuery, [`%${query}%`], (_, results) => {
    return res.status(200).json({ advertisements: results });
  });
});

const htmlEncode = (str) =>
  String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

// 2.1. Reflected (non‑persistent) XSS Vulnerability Fix
app.get("/filter-advertisements", (req, res) => {
  // 1. Get Input
  const filterType = req.query.type;

  // FIX: Sanitize the user input before reflecting it in the HTML response
  const safeFilterType = htmlEncode(filterType);

  // 2. Filter the ads based on the provided type (or show all)
  const filteredAds = adsDb.filter(
    (ad) => ad.type.toLowerCase() === filterType.toLowerCase()
  );

  // 3. Safe Reflection
  // The sanitized 'safeFilterType' is injected into the HTML response,
  // preventing execution of any embedded scripts.
  const htmlResponse = `
    .....
      <h2>Your current filter: ${safeFilterType}</h2>
      <ul>
        ${filteredAds
          .map(
            (ad) => `<li>${htmlEncode(ad.title)} - ${htmlEncode(ad.type)}</li>`
          )
          .join("")}
      </ul>
    .....
  `;

  res.send(htmlResponse);
});

// 2.2. Persistent XSS Vulnerability
app.post("/create-advertisement", (req, res) => {
  const { title, description } = req.body;
  if (!title || !description)
    return res.status(400).json({ message: "Missing title or description" });

  // FIX: Sanitize user input before storing it
  const safeTitle = htmlEncode(title);
  const safeDescription = htmlEncode(description);
  adsDb.push({ title: safeTitle, description: safeDescription });
  return res
    .status(201)
    .json({ message: "Advertisement created successfully" });
});

app.get("/advertisements", (req, res) => {
  // Return all ads, including any with malicious scripts
  const ads = adsDb.map((ad) => ({
    title: ad.title,
    description: ad.description,
  }));
  return res.send(`<html><body><ul>
    ${ads
      .map((ad) => `<li><h3>${ad.title}</h3><p>${ad.description}</p></li>`)
      .join("")}
    </ul></body></html>`);
});

// 3. CSRF Vulnerability
const CSRF_SECRET = "super-secret-key-change-this";

// -----------------------------------------------------------
// 1️⃣ Function to generate a CSRF token (signed)
// -----------------------------------------------------------
const usedTokens = new Set();

function generateCsrfToken(userIdentifier) {
  const randomPart = crypto.randomBytes(16).toString("hex"); // random string
  const data = `${userIdentifier}:${randomPart}`;

  // Create an HMAC signature bound to the user (e.g., cookie value)
  const signature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(data)
    .digest("hex");

  usedTokens.add(randomPart);
  return `${randomPart}.${signature}`;
}

// -----------------------------------------------------------
// 2️⃣ Function to verify the CSRF token
// -----------------------------------------------------------
function verifyCsrfToken(token, userIdentifier) {
  if (!token) return false;
  const [randomPart, signature] = token.split(".");

  const expectedSignature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(`${userIdentifier}:${randomPart}`)
    .digest("hex");

  if (!usedTokens.has(randomPart)) return false; // Token reuse check
  usedTokens.delete(randomPart); // Invalidate token after use

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// -----------------------------------------------------------
// 3️⃣ API to generate and send the CSRF token
// -----------------------------------------------------------
app.get("/csrf-token", (req, res) => {
  const userCookie = req.cookies.userId || "anonymous"; // or JWT sub
  const token = generateCsrfToken(userCookie);
  res.cookie("csrf_token", token, {
    httpOnly: false,
    secure: false,
    maxAge: 3600000,
    sameSite: "Strict",
  });
  return res.status(200).json({ csrfToken: token });
});

app.delete("/delete-account", (req, res) => {
  // 1. Authenticate User via JWT in Cookie
  const user = getUserFromRequest(req);
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  const userId = user.id;

  // 2. CSRF Token Validation
  const csrfToken = req.cookies["csrf_token"];
  const userCookie = req.cookies.userId || "anonymous";
  if (!verifyCsrfToken(csrfToken, userCookie)) {
    return res.status(403).json({ message: "Invalid CSRF token" });
  }

  // 3. Proceed with Account Deletion
  db.query("DELETE FROM users WHERE id = ?", [userId], () => {
    return res.status(200).json({ message: "Account deleted successfully" });
  });
});

// 4. IDOR Vulnerability Fix
// authMiddleware extracts and verifies JWT, attaching user info to req.user
const authMiddleware = (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
};

app.use(authMiddleware);
app.patch("/advertisements/:id", authMiddleware, (req, res) => {
  const adId = req.params.id;
  const { title, description } = req.body;
  const userId = req.user.userId;
  // FIX: Verify ownership before allowing update
  const sqlQuery = "SELECT * FROM advertisements WHERE id = ? AND owner_id = ?";
  db.query(sqlQuery, [adId, userId], (_, results) => {
    if (results.length === 0) {
      return res.status(403).json({ message: "Forbidden: Not your ad" });
    }
    const updateQuery =
      "UPDATE advertisements SET title = ?, description = ? WHERE id = ?";
    const params = [title, description, adId];
    db.query(updateQuery, params, () => {
      return res
        .status(200)
        .json({ message: "Advertisement updated successfully" });
    });
  });
});

// 5. File Upload Vulnerability Fix
const UPLOAD_DIR = path.resolve(__dirname, "uploads");

// ensure upload directory exists (no execute perms in prod)
await fs.mkdir(UPLOAD_DIR, { recursive: true });

const storage = multer.memoryStorage(); // keep in memory for validation
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max per file
});

const checkUserQuota = async (req, res, next) => {
  const user = getUserFromRequest(req);
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  const quotaLimit = 10 * 1024 * 1024; // 10 MB quota
  const usedSpace = await getUserUsedStorage(user.id); // Implement this function
  if (usedSpace + req.file.size > quotaLimit) {
    return res.status(413).json({ message: "Storage quota exceeded" });
  }
  next();
};

app.post(
  "/upload-profile-picture",
  authMiddleware,
  checkUserQuota,
  upload.single("profile_picture"),
  async (req, res) => {
    const user = getUserFromRequest(req);
    if (!user) return res.status(401).json({ message: "Unauthorized" });

    const file = req.file;
    if (!file) return res.status(400).json({ message: "No file uploaded" });

    // 1. Check magic bytes / sniff file content
    const ft = await FileType.fromBuffer(req.file.buffer);
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!ft || !allowed.includes(ft.mime)) {
      return res.status(400).json({ error: "Unsupported file type" });
    }

    // 2. Generate a safe filename and write to quarantine
    const safeName = crypto.randomUUID() + "." + ft.ext;
    const destPath = path.join(UPLOAD_DIR, safeName);

    // 3. Remove the previous profile picture if exists
    if (user.profile_picture_path) await fs.unlink(user.profile_picture_path);

    await fs.writeFile(destPath, req.file.buffer, { flag: "wx" }); // fail if exists

    // 3. Optionally call an AV scanner here; move to permanent storage only after scanning
    await scanWithAV(destPath);

    // 4. process/re-encode image (resize, strip EXIF) before serving
    await reencodeImage(destPath);

    // 5. Save file path and file name to user's profile in DB
    await db.query(
      "UPDATE users SET profile_picture_path = ?, profile_picture_name = ? WHERE id = ?",
      [destPath, safeName, user.id]
    );

    // 6. Update user's storage usage
    await addUserStorageUsage(user.id, req.file.size); // track user storage usage

    return res.status(200).json({ message: "File uploaded successfully" });
  }
);

// Start the server
app.listen(3000, () => {
  console.log("Secure app listening on port 3000");
});
