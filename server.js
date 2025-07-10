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
    exec(`whois ${ip}`, (err, stdout, stderr) => {
      if (err || stderr) return resolve("WHOIS failed or not available.");
      const match = stdout.match(/(?:OrgName|Org-Name|netname|organisation|owner):\s*(.*)/i);
      resolve(match ? match[1].trim() : "Owner info not found.");
    });
  });
}

// DNSBL checks
async function checkSURBL(domain) {
  try {
    await dns.resolve4(`${domain}.multi.surbl.org`);
    return true;
  } catch {
    return false;
  }
}

async function checkDBL(domain) {
  try {
    await dns.resolve4(`${domain}.dbl.spamhaus.org`);
    return true;
  } catch {
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
