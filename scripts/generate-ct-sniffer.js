const fs = require("fs");

const CT_LOG = "https://ct.googleapis.com/logs/us1/argon2026h2/ct/v1";
const PAGE_SIZE = 32;
const MAX_PAGES = 50;

async function getJSON(url) {
  const res = await fetch(url, {
    headers: {
      "User-Agent": "0x7kQ2-ct-sniffer"
    }
  });

  if (!res.ok) {
    throw new Error(`GET ${url} failed: ${res.status} ${res.statusText}`);
  }

  return res.json();
}

function escapeXML(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function certFromLeaf(leafB64) {
  const leaf = Buffer.from(leafB64, "base64");
  const entryType = leaf.readUInt16BE(10);
  let o = 12;

  if (entryType === 0) {
    const len = (leaf[o] << 16) | (leaf[o + 1] << 8) | leaf[o + 2];
    o += 3;
    return leaf.subarray(o, o + len);
  }

  if (entryType === 1) {
    o += 32;
    const len = (leaf[o] << 16) | (leaf[o + 1] << 8) | leaf[o + 2];
    o += 3;
    return leaf.subarray(o, o + len);
  }

  return null;
}

function dnsNames(der) {
  const names = [];
  let i = 0;

  while (i < der.length - 2) {
    if (der[i] === 0x82 && der[i + 1] < 0x80) {
      const len = der[i + 1];
      const raw = der.subarray(i + 2, i + 2 + len).toString("ascii");
      if (
        /^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/.test(
          raw
        )
      ) {
        names.push(raw);
      }
      i += 2 + len;
    } else {
      i += 1;
    }
  }

  const seen = new Set();
  const out = [];
  for (const n of names) {
    const key = n.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(n);
  }
  return out;
}

function issuerShort(der) {
  const oid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]);
  const j = der.indexOf(oid);
  if (j < 0) return "?";

  const k = j + oid.length;
  if (k >= der.length) return "?";

  const tag = der[k];
  const len = der[k + 1];
  if (![0x0c, 0x13, 0x16].includes(tag) || len >= 0x80) return "?";

  return der.subarray(k + 2, k + 2 + len).toString("utf8") || "?";
}

function dedupe(rows, limit) {
  const seen = new Set();
  const out = [];

  for (const row of rows) {
    const key = row.name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
    if (out.length >= limit) break;
  }

  return out;
}

function clip(str, n) {
  const s = String(str);
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

async function collectFromCT() {
  const sth = await getJSON(`${CT_LOG}/get-sth`);
  let end = sth.tree_size - 1;

  const wild = [];
  const dns = [];

  for (let page = 0; page < MAX_PAGES; page++) {
    if (wild.length >= 14 && dns.length >= 14) break;
    if (end < 0) break;

    const start = Math.max(0, end - (PAGE_SIZE - 1));
    const batch = await getJSON(
      `${CT_LOG}/get-entries?start=${start}&end=${end}`
    );
    const entries = batch.entries || [];

    for (let i = entries.length - 1; i >= 0; i--) {
      const cert = certFromLeaf(entries[i].leaf_input);
      if (!cert || !cert.length) continue;

      const names = dnsNames(cert);
      if (!names.length) continue;

      const issuer = clip(issuerShort(cert), 28);

      for (const name of names) {
        const row = { name, issuer };
        if (name.startsWith("*.")) wild.push(row);
        else dns.push(row);
      }
    }

    end = start - 1;
    if (start === 0) break;
  }

  return {
    treeSize: sth.tree_size,
    wildcards: dedupe(wild, 6),
    names: dedupe(dns, 6)
  };
}

(async () => {
  fs.mkdirSync("svgs", { recursive: true });

  const { treeSize, wildcards, names } = await collectFromCT();

  if (!wildcards.length && !names.length) {
    throw new Error("No CT DNS names found in recent log window");
  }

  const W = 1400;
  const H = 210;
  const startY = 62;
  const lineHeight = 22;
  const leftX = 28;
  const rightX = 720;

  const leftRows = wildcards
    .map((v, i) => {
      const y = startY + i * lineHeight;
      return `
      <circle cx="${leftX}" cy="${y - 4}" r="2.5" fill="#ff4d4d"/>
      <text x="${leftX + 12}" y="${y}" fill="#79b8ff" font-size="13" font-family="Arial">${escapeXML(clip(v.name, 42))}</text>
      <text x="690" y="${y}" fill="#6e7681" font-size="11" font-family="Arial" text-anchor="end">${escapeXML(clip(v.issuer, 14))}</text>
    `;
    })
    .join("");

  const rightRows = names
    .map((v, i) => {
      const y = startY + i * lineHeight;
      return `
      <circle cx="${rightX}" cy="${y - 4}" r="2.5" fill="#58a6ff"/>
      <text x="${rightX + 12}" y="${y}" fill="#c9d1d9" font-size="13" font-family="Arial">${escapeXML(clip(v.name, 42))}</text>
      <text x="1372" y="${y}" fill="#6e7681" font-size="11" font-family="Arial" text-anchor="end">${escapeXML(clip(v.issuer, 14))}</text>
    `;
    })
    .join("");

  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <rect width="${W}" height="${H}" rx="12" fill="#0d1117"/>
  <rect x="1" y="1" width="${W - 2}" height="${H - 2}" rx="11" fill="none" stroke="#21262d"/>

  <!-- slim header -->
  <rect x="0" y="0" width="${W}" height="36" rx="12" fill="#161b22"/>
  <rect x="0" y="24" width="${W}" height="12" fill="#161b22"/>
  <rect x="0" y="35" width="${W}" height="1" fill="#30363d"/>

  <text x="28" y="24" fill="#8b949e" font-size="12" font-family="Arial" font-weight="bold" letter-spacing="1.5">CT SNIFFER</text>
  <text x="130" y="24" fill="#ff4d4d" font-size="12" font-family="Arial">wildcards</text>
  <text x="210" y="24" fill="#6e7681" font-size="12" font-family="Arial">/</text>
  <text x="222" y="24" fill="#58a6ff" font-size="12" font-family="Arial">fresh names</text>
  <text x="1372" y="24" fill="#6e7681" font-size="11" font-family="Arial" text-anchor="end">Argon2026h2 · ${escapeXML(String(treeSize))}</text>

  <!-- column labels -->
  <text x="${leftX}" y="52" fill="#ff7b72" font-size="11" font-family="Arial" font-weight="bold">WILDCARD</text>
  <text x="${rightX}" y="52" fill="#58a6ff" font-size="11" font-family="Arial" font-weight="bold">NAME</text>

  <line x1="710" y1="44" x2="710" y2="192" stroke="#21262d"/>

  ${leftRows}
  ${rightRows}

  <text x="28" y="200" fill="#484f58" font-size="11" font-family="Arial">certificate transparency · updates every 30m</text>
</svg>
`;

  fs.writeFileSync("svgs/ct-sniffer.svg", svg);
  console.log(
    `Generated ct-sniffer.svg (wildcards=${wildcards.length}, names=${names.length}, tree=${treeSize}, ${W}x${H})`
  );
})();
