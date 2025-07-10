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
    exec(`whois ${ip}`, { maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err || !stdout) {
        return resolve("WHOIS failed or unavailable.");
      }

      const orgFields = [
        "OrgName", "org-name", "organisation", "owner", "netname", "descr", "CustName", "Org"
      ];

      const lines = stdout.split("\n");
      for (const line of lines) {
        const cleaned = line.trim();
        const match = cleaned.match(/^([A-Za-z\-]+)\s*:\s*(.+)$/);

        if (match) {
          const key = match[1].toLowerCase();
          const value = match[2].trim();

          if (orgFields.some(f => f.toLowerCase() === key) && value.length > 2) {
            return resolve(value);
          }
        }
      }

      return resolve("Owner info not found.");
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

exec("which whois", (err, stdout) => {
  console.log("WHOIS path:", stdout || "not found");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
