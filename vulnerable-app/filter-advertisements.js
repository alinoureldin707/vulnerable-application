/* -----------------------------------------------------------------------------
Reflected XSS Vulnerability:
- The /filter-advertisements endpoint reflects user input directly into the HTML response without proper sanitization or encoding.
- An attacker can exploit this by crafting a URL with a malicious script in the 'type' query parameter.
- Example: Accessing /filter-advertisements?type=<script>alert('XSS')</script> will execute the alert when the page is loaded.
-----------------------------------------------------------------------------*/
app.get("/filter-advertisements", (req, res) => {
  // 1. Get the filter type from the query string (?type=...)
  // This is the user-controlled input that is about to be reflected.
  const filterType = req.query.type;

  // 2. Filter the ads based on the provided type (or show all)
  const filteredAds = ads.filter(
    (ad) => ad.type.toLowerCase() === filterType.toLowerCase()
  );

  // 3. ISSUE: UNSAFE REFLECTION
  // The raw, unsanitized 'filterType' is injected directly into the HTML response
  // without encoding, allowing any script tag within 'filterType' to execute.
  const htmlResponse = `
    .....
      <h2>Your current filter: ${filterType}</h2>
      <ul>
        ${filteredAds.map((ad) => `<li>${ad.title} - ${ad.type}</li>`).join("")}
      </ul>
    .....  
    `;

  res.send(htmlResponse);
});

/* -----------------------------------------------------------------------------
Reflected XSS Exploit Example:
- An attacker can exploit the reflected XSS vulnerability in the /filter-advertisements endpoint
- by crafting a malicious URL that includes a script in the 'type' parameter.
- Example: By visiting /filter-advertisements?type=<script>alert('XSS')</script>, the attacker can execute arbitrary JavaScript in the victim's browser.
-----------------------------------------------------------------------------*/
fetch("/filter-advertisements?type=<script>alert('XSS')</script>", {
  method: "GET",
  headers: { "Content-Type": "text/html" },
});
