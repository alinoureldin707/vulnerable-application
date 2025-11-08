/*-----------------------------------------------------------------------------
File Upload Vulnerability Fix:
- Checks file type, size, and content before uploading.
- Sanitizes file names and paths before saving to the database.
- Implements user storage quotas to prevent abuse.
-----------------------------------------------------------------------------*/

const UPLOAD_DIR = path.resolve(__dirname, "uploads_secure");

// ensure upload directory exists
await fs.mkdir(UPLOAD_DIR, { recursive: true });

const storage = multer.memoryStorage(); // keep in memory for validation
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max per file
});

const checkUserQuota = async (req, res, next) => {
  const user = req.user;
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  const quotaLimit = 10 * 1024 * 1024; // 10 MB quota
  const usedSpace = await getUserUsedStorage(user.id);
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
    const user = req.user;
    if (!user) return res.status(401).json({ message: "Unauthorized" });

    const file = req.file;
    if (!file) return res.status(400).json({ message: "No file uploaded" });

    // CSRF Protection could be added here as well
    const csrfToken = req.headers["x-csrf-token"];

    if (!verifyCsrfToken(csrfToken, userId)) {
      return res.status(403).json({ message: "Invalid or expired CSRF token" });
    }

    // 1. Check magic bytes / sniff file content
    const ft = await FileType.fromBuffer(req.file.buffer);
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!ft || !allowed.includes(ft.mime)) {
      return res.status(400).json({ error: "Unsupported file type" });
    }

    // 2. Generate a safe filename
    const safeName = crypto.randomUUID() + "." + ft.ext;
    const destPath = path.join(UPLOAD_DIR, safeName);

    // 3. Remove the previous profile picture if exists -> protect against orphaned files
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
    await addUserStorageUsage(user.id, req.file.size);

    return res.status(200).json({ message: "File uploaded successfully" });
  }
);
