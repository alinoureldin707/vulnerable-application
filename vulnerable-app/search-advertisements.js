/* -----------------------------------------------------------------------------
SQL Injection Vulnerability:
- This function is insecure because user inputs (query) are directly inserted into the SQL query string without using parameters.
- An attacker could manipulate the input to alter the query logic and execute arbitrary SQL commands.
- Impact: attacker could retrieve unauthorized data or modify the database.
-----------------------------------------------------------------------------*/
app.get("/search-advertisements", (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ message: "Missing search query" });

  // ISSUE: SQL Injection Vulnerability - direct interpolation of user inputs
  // The user input is concatenated directly into the SQL command.
  // Example: If query is set to "'; DROP TABLE advertisements; --", it could delete the table.
  const sqlQuery = `SELECT * FROM advertisements WHERE title LIKE '%${query}%'`;

  const results = db.query(sqlQuery);
  return res.status(200).json({ advertisements: results });
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
