const express = require("express");
const dns = require("dns").promises;
const whoiser = require("whoiser");
const { exec } = require("child_process");
const path = require("path");

const app = express();
app.use(express.static("public"));

// WHOIS IP resolver
function whoisIP(ip) {
  return new Promise((resolve) => {
    exec(`whois ${ip}`, (err, stdout) => {
      if (err) return resolve("WHOIS failed.");
      
      const lines = stdout.split("\n").map(line => line.trim());
      const orgLine = lines.find(line =>
        /^(OrgName|Org-Name|Orgname|netname|owner|CustName|descr):/i.test(line)
      );
      if (orgLine) {
        const [, org] = orgLine.split(/:\s+/);
        return resolve(org.trim());
      }

      resolve("Owner info not found.");
    });
  });
}


// DNSBL checks
async function checkSURBL(domain) {
  const clean = domain
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0];

  const query = `${clean}.multi.surbl.org`;

  try {
    const records = await dns.resolve4(query);
    return records.some(ip => ip.startsWith("127."));
  } catch (err) {
    if (err.code === "ENOTFOUND") return false;
    return false; // any other error — treat as not listed
  }
}

async function checkDBL(domain) {
  const query = `${domain}.dbl.spamhaus.org`;

  try {
    const records = await dns.resolve4(query);
    // DBL returns IPs like 127.0.1.x for matches
    return records.some(ip => ip.startsWith("127."));
  } catch (err) {
    if (err.code === "ENOTFOUND") return false;
    return false;
  }
}

app.get("/check", async (req, res) => {
  const domain = req.query.domain?.trim();
  if (!domain) return res.status(400).json({ error: "Missing domain parameter." });

  try {
    const whoisData = await whoiser(domain);
    const aRecords = await dns.resolve4(domain);
    const ip = aRecords[0];

    const mx = await dns.resolveMx(domain);
    const ns = await dns.resolveNs(domain);
    const ipOwner = ip ? await whoisIP(ip) : "N/A";
    const [surbl, dbl] = await Promise.all([checkSURBL(domain), checkDBL(domain)]);

    res.json({
      domain,
      aRecord: ip,
      mx: mx.map(m => m.exchange),
      ns,
      whoisStatus: whoisData[domain]?.["domain status"] || [],
      ipOwner,
      blacklist: { surbl, dbl }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
