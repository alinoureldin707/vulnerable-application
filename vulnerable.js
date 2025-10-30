const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const db = require("./db"); // Assume this is a configured database connection
const JWT_SECRET = "secretkey";
const app = express();
const multer = require("multer");
const fs = require("fs/promises");
const path = require("path");

app.use(bodyParser.json());
app.use(cookieParser());

// 1.1. SQL Injection Vulnerability
// This code is intentionally vulnerable to demonstrate SQL injection risks.
app.post("/login", (req, res) => {
  // 1. Get Input
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Missing credentials" });

  // 2. Prepare the SQL Query
  // ISSUE: SQL Injection Vulnerability - direct interpolation of user inputs
  // The user input is concatenated directly into the SQL command.
  // An attacker could exploit this by injecting malicious SQL code.
  const sqlQuery = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;

  let user = null;

  // 3. Execute the Query
  db.query(sqlQuery, (_, results) => {
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

// 1.2. SQL Injection Vulnerability
app.get("/search-advertisements", (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ message: "Missing search query" });

  // ISSUE: SQL Injection Vulnerability - direct interpolation of user inputs
  // The user input is concatenated directly into the SQL command.
  // Example: If query is set to "'; DROP TABLE advertisements; --", it could delete the table.
  const sqlQuery = `SELECT * FROM advertisements WHERE title LIKE '%${query}%'`;

  db.query(sqlQuery, (_, results) => {
    return res.status(200).json({ advertisements: results });
  });
});

// 2. Reflected (non‑persistent) XSS Vulnerability
app.get("/filter-advertisements", (req, res) => {
  // 1. Get the filter type from the query string (?type=...)
  // This is the user-controlled input that is about to be reflected.
  const filterType = req.query.type;

  // 2. Filter the ads based on the provided type (or show all)
  const filteredAds = adsDb.filter(
    (ad) => ad.type.toLowerCase() === filterType.toLowerCase()
  );

  // 3. *** VULNERABILITY HERE: UNSAFE REFLECTION ***
  // The raw, unsanitized 'filterType' is injected directly into the HTML response
  // without encoding, allowing any script tag within 'filterType' to execute.
  const htmlResponse = `
    .....
      <h2>Your current filter: ${filterType}</h2>
      <ul>
        ${filteredAds.map((ad) => `<li>${ad.title} - ${ad.type}</li>`).join("")}
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

  // ISSUE: Persistent XSS Vulnerability - unsanitized user input
  adsDb.push({ title, description });
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
app.delete("/delete-account", (req, res) => {
  // 1. Authenticate User via JWT in Cookie
  const user = getUserFromRequest(req);
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  const userId = user.id;

  // 2. Delete User Account
  db.query("DELETE FROM users WHERE id = ?", [userId], () => {
    return res.status(200).json({ message: "Account deleted successfully" });
  });
});

// 4. IDOR Vulnerability
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

  // ISSUE: IDOR Vulnerability - no check if the user owns the advertisement
  const sqlQuery =
    "UPDATE advertisements SET title = ?, description = ? WHERE id = ?";
  const params = [title, description, adId];
  db.query(sqlQuery, params, () => {
    return res
      .status(200)
      .json({ message: "Advertisement updated successfully" });
  });
});

// 5. File Upload Vulnerability
const UPLOAD_DIR = path.resolve(__dirname, "uploads");

// ensure upload directory exists
await fs.mkdir(UPLOAD_DIR, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
});
const upload = multer({ storage: storage });

app.post(
  "/upload-profile-picture",
  upload.single("profile_picture"),
  async (req, res) => {
    const user = getUserFromRequest(req);
    if (!user) return res.status(401).json({ message: "Unauthorized" });

    const file = req.file;
    if (!file) return res.status(400).json({ message: "No file uploaded" });

    const fileName = file.filename;
    const filePath = path.join(UPLOAD_DIR, fileName);

    await fs.writeFile(filePath, file.buffer);

    // Save file path and file name to user's profile in DB
    await db.query(
      "UPDATE users SET profile_picture_path = ?, profile_picture_name = ? WHERE id = ?",
      [filePath, fileName, user.id]
    );

    return res.status(200).json({ message: "File uploaded successfully" });
  }
);

// Start the server
app.listen(3000, () => {
  console.log("Vulnerable app listening on port 3000");
});
