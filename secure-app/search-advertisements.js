/*-----------------------------------------------------------------------------
SQL Injection Fix:
- This function has been secured by using parameterized queries to handle user inputs safely.
- User inputs (query) are passed as parameters rather than being directly concatenated into the SQL query string.
- This prevents attackers from manipulating the query logic, thereby mitigating SQL injection risks.
- Impact: prevents unauthorized data retrieval and ensures database integrity.
-----------------------------------------------------------------------------*/

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
