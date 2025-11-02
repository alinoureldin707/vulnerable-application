/* -----------------------------------------------------------------------------
Persistent XSS Vulnerability Fix:
- The /create-advertisement endpoint now sanitizes user input before storing it.
- A helper function 'htmlEncode' is used to encode special characters in the title and description.
- This prevents execution of any embedded scripts when the advertisements are later viewed.
-----------------------------------------------------------------------------*/
const htmlEncode = (str) =>
  String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

app.post("/create-advertisement", (req, res) => {
  const { title, description } = req.body;
  if (!title || !description)
    return res.status(400).json({ message: "Missing title or description" });

  // FIX: Sanitize user input before storing it
  const safeTitle = htmlEncode(title);
  const safeDescription = htmlEncode(description);
  adsDb.push({ title: safeTitle, description: safeDescription });
  return res
    .status(201)
    .json({ message: "Advertisement created successfully" });
});

/* -----------------------------------------------------------------------------
Persistent XSS Protection example:
- An attacker attempts to exploit the persistent XSS vulnerability by submitting a malicious advertisement.
- However, due to the implemented sanitization, the script will not execute when viewed.
-----------------------------------------------------------------------------*/
fetch("/create-advertisement", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    title: "<script>alert('XSS')</script>",
    description: "This is a malicious advertisement.",
  }),
});
fetch("/advertisements", {
  method: "GET",
  headers: { "Content-Type": "text/html" },
})
  .then((res) => res.text())
  .then((html) => {
    document.body.innerHTML += html;
    // The alert will NOT execute due to sanitization
  });
