/*-----------------------------------------------------------------------------
IDOR Vulnerability Fix:
- Ensures that users can only update advertisements they own.
- Checks ownership before allowing updates.
- Uses parameterized queries to prevent SQL injection.

CSRF Protection:
- Implements CSRF token verification to protect against CSRF attacks.
-----------------------------------------------------------------------------*/
app.patch("/advertisements/:id", authMiddleware, (req, res) => {
  const adId = req.params.id;
  const { title, description } = req.body;
  const userId = req.user.userId;

  // CSRF Protection could be added here as well
  const csrfToken = req.headers["x-csrf-token"];

  if (!verifyCsrfToken(csrfToken, userId)) {
    return res.status(403).json({ message: "Invalid or expired CSRF token" });
  }

  // FIX: Verify ownership before allowing update
  const sqlQuery = "SELECT * FROM advertisements WHERE id = ? AND owner_id = ?";
  db.query(sqlQuery, [adId, userId], (_, results) => {
    if (results.length === 0) {
      return res.status(403).json({ message: "Forbidden: Not your ad" }); // Not the owner
    }
    const updateQuery =
      "UPDATE advertisements SET title = ?, description = ? WHERE id = ?"; // Safe parameterized query

    const params = [title, description, adId];
    db.query(updateQuery, params, () => {
      return res
        .status(200)
        .json({ message: "Advertisement updated successfully" });
    });
  });
});

/*-----------------------------------------------------------------------------
IDOR Protection example:
- An attacker attempts to exploit the IDOR vulnerability in the /advertisements/:id endpoint by sending a request to update an advertisement they do not own.
- However, due to the ownership check, the request is denied with a 403 Forbidden response.
-----------------------------------------------------------------------------*/
fetch("/advertisements/123", {
  method: "PATCH",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    title: "Hacked Title",
    description: "This advertisement has been defaced by an attacker.",
  }),
  credentials: "include", // include cookies for authentication
}).then((res) => {
  if (res.status === 403) {
    console.log("Update denied: Not your ad");
  }
});
