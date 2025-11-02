/*-----------------------------------------------------------------------------
IDOR Vulnerability:
- This function is insecure because it allows any authenticated user to update any advertisement by specifying its ID in the URL.
- There is no check to verify that the user owns the advertisement they are trying to update.
- Impact: an attacker could modify or deface advertisements they do not own.

SQL Injection:
- This function is vulnerable to SQL injection attacks because it directly interpolates user input into the SQL query string.
- Impact: An attacker could manipulate the query by injecting malicious SQL code, potentially gaining unauthorized access to or modifying data.
-----------------------------------------------------------------------------*/
app.patch("/advertisements/:id", authMiddleware, (req, res) => {
  const adId = req.params.id;
  const { title, description } = req.body;

  // ISSUE: IDOR Vulnerability - no check if the user owns the advertisement
  const sqlQuery = `UPDATE advertisements SET title = '${title}', description = '${description}' WHERE id = ${adId}`;
  db.query(sqlQuery, () => {
    return res
      .status(200)
      .json({ message: "Advertisement updated successfully" });
  });
});

/*-----------------------------------------------------------------------------
IDOR Impact Exploit Example:
- An attacker can exploit the IDOR vulnerability in the /advertisements/:id endpoint
- by sending a request to update an advertisement they do not own.
- Example: If the attacker knows the ID of another user's advertisement, they can change its title and description.
-----------------------------------------------------------------------------*/
fetch("/advertisements/123", {
  method: "PATCH",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    title: "Hacked Title",
    description: "This advertisement has been defaced by an attacker.",
  }),
  credentials: "include", // include cookies for authentication
});
