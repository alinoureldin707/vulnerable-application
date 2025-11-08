/* -----------------------------------------------------------------------------
SQL Injection Fix:
- This function has been secured by using parameterized queries to handle user inputs safely.
- User inputs (email and password) are passed as parameters rather than being directly concatenated into the SQL query string.
- This prevents attackers from manipulating the query logic, thereby mitigating SQL injection risks.
- Impact: prevents unauthorized access by ensuring the WHERE clause cannot be altered.

Setting secure HTTP-only cookies:
- The authentication token is now set in an HTTP-only cookie with enhanced security attributes.
- 'httpOnly' to prevent client-side scripts from accessing it
- 'secure' to ensure the cookie is only sent over HTTPS
- 'sameSite' to mitigate CSRF attacks
-----------------------------------------------------------------------------*/
app.post("/login", (req, res) => {
  // 1. Get Input
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Missing credentials" });
  const hashedPassword = bcrypt.hashSync(password, 10);

  // 2. Prepare the SQL Query
  // FIX: Use parameterized queries to prevent SQL injection
  // User inputs are passed as parameters rather than being directly concatenated.
  // It treats user inputs as string literals, preventing execution of malicious SQL code.
  const sqlQuery = "SELECT * FROM users WHERE email = ? AND password = ?";

  let user = null;

  // 3. Execute the Query
  db.query(sqlQuery, [email, hashedPassword], (_, results) => {
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
  // Improved security settings for the cookie
  // 'httpOnly' to prevent client-side scripts from accessing it
  // 'secure' to ensure the cookie is only sent over HTTPS
  // 'sameSite' to mitigate CSRF attacks
  res.cookie("access_token", token, {
    maxAge: 3600000,
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });

  // 7. Return Success
  return res.status(200).json({
    status: "SUCCESS",
    message: `Welcome, ${user.email}!`,
    role: user.role,
  });
});
