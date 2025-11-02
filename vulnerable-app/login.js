/* -----------------------------------------------------------------------------
SQL Injection Vulnerability:
- This function is insecure because user inputs (email and password) are directly inserted into the SQL query string without using parameters.
- An attacker could manipulate the input to alter the query logic and bypass authentication or access unauthorized data.
- Impact: attacker could make the WHERE clause always true.

CSRF Vulnerability in Cookie Settings:
- The authentication token is set in a cookie without proper security attributes.
- 'secure' is set to false, allowing the cookie to be sent over unencrypted HTTP connections.
- 'sameSite' is set to 'Lax', which provides limited protection against CSRF attacks.
-----------------------------------------------------------------------------*/
app.post("/login", (req, res) => {
  // 1. Get Input
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Missing credentials" });
  const hashedPassword = bcrypt.hashSync(password, 10);

  // 2. Prepare the SQL Query
  // ISSUE: SQL Injection Vulnerability - direct interpolation of user inputs
  // The user input is concatenated directly into the SQL command.
  const sqlQuery = `SELECT * FROM users WHERE email = '${email}' AND password = '${hashedPassword}'`;

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

  // 6. Set Cookie
  res.cookie("access_token", token, { maxAge: 3600000 });

  // 7. Return Success
  return res.status(200).json({
    status: "SUCCESS",
    message: `Welcome, ${user.email}!`,
    role: user.role,
  });
});

/* -----------------------------------------------------------------------------
SQL Injection Impact Exploit Example:
- An attacker can exploit the SQL injection vulnerability in the /search-advertisements endpoint
- by crafting a malicious input that alters the SQL query logic.
- Example: By setting the query parameter to "'; DROP TABLE advertisements; --", the attacker can terminate the original query and execute a destructive command.
-----------------------------------------------------------------------------*/
fetch("/search-advertisements", {
  method: "GET",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    query: "'; DROP TABLE advertisements; --",
  }),
});
