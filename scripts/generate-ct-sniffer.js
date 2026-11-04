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
    wildcards: dedupe(wild, 10),
    names: dedupe(dns, 10)
  };
}

(async () => {
  fs.mkdirSync("svgs", { recursive: true });

  const { treeSize, wildcards, names } = await collectFromCT();

  if (!wildcards.length && !names.length) {
    throw new Error("No CT DNS names found in recent log window");
  }

  const leftX = 40;
  const rightX = 720;
  const startY = 110;
  const lineHeight = 34;

  const leftRows = wildcards
    .map((v, i) => {
      const y = startY + i * lineHeight;
      return `
      <text x="${leftX + 20}" y="${y}" fill="#58a6ff" font-size="15" font-family="Arial">${escapeXML(clip(v.name, 34))}</text>
      <text x="${leftX + 390}" y="${y}" fill="#8b949e" font-size="14" font-family="Arial">${escapeXML(clip(v.issuer, 18))}</text>
    `;
    })
    .join("");

  const rightRows = names
    .map((v, i) => {
      const y = startY + i * lineHeight;
      return `
      <text x="${rightX + 20}" y="${y}" fill="#c9d1d9" font-size="15" font-family="Arial">${escapeXML(clip(v.name, 34))}</text>
      <text x="${rightX + 390}" y="${y}" fill="#8b949e" font-size="14" font-family="Arial">${escapeXML(clip(v.issuer, 18))}</text>
    `;
    })
    .join("");

  const svg = `
<svg
  xmlns="http://www.w3.org/2000/svg"
  width="1400"
  height="520"
  viewBox="0 0 1400 520"
>

  <rect width="1400" height="520" fill="#0d1117"/>

  <!-- LEFT PANEL -->
  <rect
    x="${leftX}"
    y="40"
    rx="20"
    ry="20"
    width="620"
    height="390"
    fill="#161b22"
    stroke="#30363d"
  />

  <!-- RIGHT PANEL -->
  <rect
    x="${rightX}"
    y="40"
    rx="20"
    ry="20"
    width="620"
    height="390"
    fill="#161b22"
    stroke="#30363d"
  />

  <!-- LEFT TITLE -->
  <text x="${leftX + 20}" y="75" fill="#ffffff" font-size="26" font-family="Arial" font-weight="bold">Live</text>
  <text x="${leftX + 90}" y="75" fill="#ff4d4d" font-size="26" font-family="Arial" font-weight="bold">Wildcards</text>

  <!-- RIGHT TITLE -->
  <text x="${rightX + 20}" y="75" fill="#ff9f1a" font-size="26" font-family="Arial" font-weight="bold">Fresh</text>
  <text x="${rightX + 110}" y="75" fill="#58a6ff" font-size="26" font-family="Arial" font-weight="bold">CT</text>
  <text x="${rightX + 160}" y="75" fill="#ffffff" font-size="26" font-family="Arial" font-weight="bold">Names</text>

  ${leftRows}
  ${rightRows}

  <!-- FOOTER -->
  <text x="40" y="475" fill="#8b949e" font-size="15" font-family="Arial">
    Source: Certificate Transparency — Google Argon2026h2
  </text>

  <text x="40" y="500" fill="#8b949e" font-size="15" font-family="Arial">
    Auto updates every 30 minutes · tree ${escapeXML(String(treeSize))}
  </text>

</svg>
`;

  fs.writeFileSync("svgs/ct-sniffer.svg", svg);
  console.log(
    `Generated ct-sniffer.svg (wildcards=${wildcards.length}, names=${names.length}, tree=${treeSize})`
  );
})();
