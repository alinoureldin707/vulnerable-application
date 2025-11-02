/* -----------------------------------------------------------------------------
Reflected XSS Vulnerability Fix:
- The /filter-advertisements endpoint has been secured by sanitizing user input before reflecting it in the HTML response.
- A helper function 'htmlEncode' is used to encode special characters in the 'type' query parameter.
- This prevents execution of any embedded scripts, mitigating the reflected XSS vulnerability.
-----------------------------------------------------------------------------*/
const htmlEncode = (str) =>
  String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

app.get("/filter-advertisements", (req, res) => {
  // 1. Get Input
  const filterType = req.query.type;

  // FIX: Sanitize the user input before reflecting it in the HTML response
  const safeFilterType = htmlEncode(filterType);

  // 2. Filter the ads based on the provided type (or show all)
  const filteredAds = adsDb.filter(
    (ad) => ad.type.toLowerCase() === filterType.toLowerCase()
  );

  // 3. Safe Reflection
  // The sanitized 'safeFilterType' is injected into the HTML response,
  // preventing execution of any embedded scripts.
  const htmlResponse = `
    .....
      <h2>Your current filter: ${safeFilterType}</h2>
      <ul>
        ${filteredAds.map((ad) => `<li>${ad.title} - ${ad.type}</li>`).join("")}
      </ul>
    .....
  `;

  res.send(htmlResponse);
});
