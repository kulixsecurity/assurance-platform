export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/import-csv") {
      const csv = await request.text();
      const parsed = parseCsv(csv);

      if (parsed.length === 0) {
        return Response.json({ message: "No rows found" }, { status: 400 });
      }

      const first = parsed[0];
      const required = [
        "definition.id",
        "definition.name",
        "definition.cvss3.base_score",
        "definition.vpr.score",
        "definition.vpr_v2.drivers_on_cisa_kev",
        "first_observed",
        "asset.name",
        "severity"
      ];

      for (const col of required) {
        if (!(col in first)) {
          return Response.json(
            { message: `Missing required column: ${col}` },
            { status: 400 }
          );
        }
      }

      const grouped = new Map();

      for (const row of parsed) {
        const pluginId = String(row["definition.id"] || "").trim();
        if (!pluginId) continue;

        const title = String(row["definition.name"] || "").trim();
        const severity = String(row["severity"] || "").trim() || "Unknown";
        const cvss = toNumber(row["definition.cvss3.base_score"]);
        const vpr = toNumber(row["definition.vpr.score"]);
        const kev = normalizeKev(row["definition.vpr_v2.drivers_on_cisa_kev"]);
        const firstSeen = String(row["first_observed"] || "").trim();
        const assetName = String(row["asset.name"] || "").trim();

        if (!grouped.has(pluginId)) {
          grouped.set(pluginId, {
            plugin_id: pluginId,
            title,
            severity,
            cvss,
            vpr,
            kev,
            first_seen: firstSeen,
            assets: new Set()
          });
        }

        const item = grouped.get(pluginId);

        if (assetName) item.assets.add(assetName);

        if (!item.title && title) item.title = title;

        if (severityRank(severity) > severityRank(item.severity)) {
          item.severity = severity;
        }

        if (cvss > item.cvss) item.cvss = cvss;
        if (vpr > item.vpr) item.vpr = vpr;
        if (kev === "true") item.kev = "true";

        if (firstSeen && (!item.first_seen || firstSeen < item.first_seen)) {
          item.first_seen = firstSeen;
        }
      }

      await env.DB.prepare("DELETE FROM findings").run();

      for (const item of grouped.values()) {
        await env.DB.prepare(
          `INSERT INTO findings
           (plugin_id, title, severity, cvss, vpr, kev, affected_assets, first_seen, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            item.plugin_id,
            item.title,
            item.severity,
            item.cvss,
            item.vpr,
            item.kev,
            item.assets.size,
            item.first_seen || null,
            "Open"
          )
          .run();
      }

      return Response.json({
        message: "CSV imported",
        vulnerabilities: grouped.size
      });
    }

    if (request.method === "POST" && url.pathname === "/update-status") {
      const data = await request.json();

      await env.DB.prepare(
        "UPDATE findings SET status = ? WHERE id = ?"
      )
        .bind(data.status, data.id)
        .run();

      return Response.json({ message: "updated" });
    }

    if (url.pathname === "/findings") {
      const { results } = await env.DB.prepare(
        `SELECT
           id,
           plugin_id,
           title,
           severity,
           cvss,
           vpr,
           kev,
           affected_assets,
           first_seen,
           status,
           CAST((julianday('now') - julianday(first_seen)) AS INTEGER) AS age_days
         FROM findings
         ORDER BY
           CASE WHEN kev = 'true' THEN 1 ELSE 0 END DESC,
           vpr DESC,
           cvss DESC,
           affected_assets DESC`
      ).all();

      return Response.json({
        total_findings: results.length,
        findings: results
      });
    }

    const { results } = await env.DB.prepare(
      `SELECT
         id,
         plugin_id,
         title,
         severity,
         cvss,
         vpr,
         kev,
         affected_assets,
         first_seen,
         status,
         CAST((julianday('now') - julianday(first_seen)) AS INTEGER) AS age_days
       FROM findings
       ORDER BY
         CASE WHEN kev = 'true' THEN 1 ELSE 0 END DESC,
         vpr DESC,
         cvss DESC,
         affected_assets DESC`
    ).all();

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let kevCount = 0;

    results.forEach((f) => {
      if (f.severity === "Critical") critical++;
      if (f.severity === "High") high++;
      if (f.severity === "Medium") medium++;
      if (f.severity === "Low") low++;
      if (f.kev === "true") kevCount++;
    });

    const rows = results.map((f) => {
      let color = "#64748b";
      if (f.severity === "Critical") color = "#ef4444";
      if (f.severity === "High") color = "#f97316";
      if (f.severity === "Medium") color = "#eab308";
      if (f.severity === "Low") color = "#22c55e";

      const kevBadge =
        f.kev === "true"
          ? `<span style="background:#991b1b;color:white;padding:4px 8px;border-radius:999px;font-size:12px;">KEV</span>`
          : "";

      return `
      <tr>
        <td>${escapeHtml(f.title)}</td>
        <td>${escapeHtml(f.plugin_id)}</td>
        <td><span style="color:${color};font-weight:bold">${escapeHtml(f.severity)}</span></td>
        <td>${f.cvss ?? ""}</td>
        <td>${f.vpr ?? ""}</td>
        <td>${kevBadge}</td>
        <td>${f.affected_assets}</td>
        <td>${f.age_days ?? ""}</td>
        <td>${escapeHtml(f.status)}</td>
        <td>
          <button onclick="updateStatus(${f.id},'In Progress')">Start</button>
          <button onclick="updateStatus(${f.id},'Resolved')">Resolve</button>
          <button onclick="updateStatus(${f.id},'Risk Accepted')">Accept</button>
        </td>
      </tr>
      `;
    }).join("");

    const html = `
    <html>
    <head>
      <title>Security Assurance Dashboard</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background: #0f172a;
          color: white;
          padding: 40px;
        }
        table {
          border-collapse: collapse;
          width: 100%;
          background: #1e293b;
        }
        th, td {
          padding: 12px;
          border-bottom: 1px solid #334155;
          text-align: left;
        }
        th {
          background: #020617;
        }
        tr:hover {
          background: #334155;
        }
        button {
          margin-right: 6px;
          padding: 6px 10px;
          border: none;
          border-radius: 4px;
          background: #2563eb;
          color: white;
          cursor: pointer;
        }
      </style>
    </head>
    <body>
      <div style="display:flex;gap:20px;margin-bottom:30px;flex-wrap:wrap;">
        <div style="background:#7f1d1d;padding:15px;border-radius:6px;">Critical: ${critical}</div>
        <div style="background:#9a3412;padding:15px;border-radius:6px;">High: ${high}</div>
        <div style="background:#854d0e;padding:15px;border-radius:6px;">Medium: ${medium}</div>
        <div style="background:#14532d;padding:15px;border-radius:6px;">Low: ${low}</div>
        <div style="background:#991b1b;padding:15px;border-radius:6px;">KEV: ${kevCount}</div>
        <div style="background:#1d4ed8;padding:15px;border-radius:6px;">Total Vulns: ${results.length}</div>
      </div>

      <h1>Security Assurance Dashboard</h1>

      <div style="margin-bottom:20px;">
        <input type="file" id="csvFile">
        <button onclick="uploadCSV()">Import Tenable CSV</button>
      </div>

      <table>
        <thead>
          <tr>
            <th>Vulnerability</th>
            <th>Plugin ID</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>VPR</th>
            <th>KEV</th>
            <th>Affected Assets</th>
            <th>Age (days)</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>

      <script>
        async function uploadCSV() {
          const file = document.getElementById("csvFile").files[0];
          if (!file) {
            alert("Choose a CSV file first");
            return;
          }

          const text = await file.text();

          const res = await fetch("/import-csv", {
            method: "POST",
            body: text
          });

          if (!res.ok) {
            const msg = await res.text();
            alert("Import failed: " + msg);
            return;
          }

          location.reload();
        }

        async function updateStatus(id, status) {
          await fetch("/update-status", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id, status })
          });

          location.reload();
        }
      </script>
    </body>
    </html>
    `;

    return new Response(html, {
      headers: { "content-type": "text/html" }
    });
  }
};

function toNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function normalizeKev(value) {
  const v = String(value || "").trim().toLowerCase();
  return v === "true" || v === "1" || v === "yes" ? "true" : "false";
}

function severityRank(severity) {
  if (severity === "Critical") return 4;
  if (severity === "High") return 3;
  if (severity === "Medium") return 2;
  if (severity === "Low") return 1;
  return 0;
}

function parseCsv(text) {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const rows = lines.filter((l) => l.trim() !== "");
  if (rows.length < 2) return [];

  const headers = splitCsvLine(rows[0]);

  return rows.slice(1).map((line) => {
    const values = splitCsvLine(line);
    const obj = {};
    headers.forEach((h, i) => {
      obj[h] = values[i] ?? "";
    });
    return obj;
  });
}

function splitCsvLine(line) {
  const result = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];

    if (ch === '"' && inQuotes && next === '"') {
      current += '"';
      i++;
      continue;
    }

    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }

    if (ch === "," && !inQuotes) {
      result.push(current.trim());
      current = "";
      continue;
    }

    current += ch;
  }

  result.push(current.trim());
  return result;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}        data.source,
        "Open",
        data.asset,
        data.owner
      )
      .run();

      return Response.json({ message: "Finding created" });
    }

    /* ------------------------------
       UPDATE STATUS
    ------------------------------ */

    if (request.method === "POST" && url.pathname === "/update-status") {

      const data = await request.json();

      await env.DB.prepare(
        "UPDATE findings SET status=? WHERE id=?"
      )
      .bind(data.status, data.id)
      .run();

      return Response.json({ message: "updated" });
    }

    /* ------------------------------
       API GET FINDINGS
    ------------------------------ */

    if (url.pathname === "/findings") {

      const { results } = await env.DB.prepare(
        "SELECT id,title,severity,source,status,asset,owner, CAST((julianday('now') - julianday(created_at)) AS INTEGER) AS age_days FROM findings ORDER BY age_days DESC"
      ).all();

      return Response.json({
        total_findings: results.length,
        findings: results
      });
    }

    /* ------------------------------
       DASHBOARD QUERY
    ------------------------------ */

    const { results } = await env.DB.prepare(
      "SELECT id,title,severity,source,status,asset,owner, CAST((julianday('now') - julianday(created_at)) AS INTEGER) AS age_days FROM findings ORDER BY age_days DESC"
    ).all();

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    results.forEach(f => {

      if (f.severity === "Critical") critical++;
      if (f.severity === "High") high++;
      if (f.severity === "Medium") medium++;
      if (f.severity === "Low") low++;

    });

    /* ------------------------------
       TABLE ROWS
    ------------------------------ */

    const rows = results.map(f => {

      let color = "#64748b";

      if (f.severity === "Critical") color = "#ef4444";
      if (f.severity === "High") color = "#f97316";
      if (f.severity === "Medium") color = "#eab308";
      if (f.severity === "Low") color = "#22c55e";

      return `
      <tr>
      <td>${f.title}</td>
      <td><span style="color:${color};font-weight:bold">${f.severity}</span></td>
      <td>${f.asset || "-"}</td>
      <td>${f.owner || "-"}</td>
      <td>${f.source}</td>
      <td>${f.status}</td>

      <td>
      <button onclick="updateStatus(${f.id},'In Progress')">Start</button>
      <button onclick="updateStatus(${f.id},'Resolved')">Resolve</button>
      <button onclick="updateStatus(${f.id},'Risk Accepted')">Accept</button>
      </td>

      <td>${f.age_days}</td>
      </tr>
      `;

    }).join("");

    /* ------------------------------
       DASHBOARD HTML
    ------------------------------ */

    const html = `
    <html>

    <head>

    <title>Security Assurance Dashboard</title>

    <style>

    body{
      font-family:Arial;
      background:#0f172a;
      color:white;
      padding:40px;
    }

    table{
      border-collapse:collapse;
      width:100%;
      background:#1e293b;
    }

    th,td{
      padding:12px;
      border-bottom:1px solid #334155;
    }

    th{
      background:#020617;
      text-align:left;
    }

    tr:hover{
      background:#334155;
    }

    button{
      margin-right:6px;
      padding:6px 10px;
      border:none;
      border-radius:4px;
      background:#2563eb;
      color:white;
      cursor:pointer;
    }

    </style>

    </head>

    <body>

    <div style="display:flex;gap:20px;margin-bottom:30px;">

      <div style="background:#7f1d1d;padding:15px;border-radius:6px;">
      Critical: ${critical}
      </div>

      <div style="background:#9a3412;padding:15px;border-radius:6px;">
      High: ${high}
      </div>

      <div style="background:#854d0e;padding:15px;border-radius:6px;">
      Medium: ${medium}
      </div>

      <div style="background:#14532d;padding:15px;border-radius:6px;">
      Low: ${low}
      </div>

    </div>

    <h1>Security Assurance Dashboard</h1>

    <button onclick="addTestFinding()" style="margin-bottom:20px;padding:10px 15px;background:#2563eb;border:none;border-radius:5px;">
    Add Test Finding
    </button>

<br><br>

<input type="file" id="csvFile">
<button onclick="uploadCSV()">Import Tenable CSV</button>

    <table>

    <thead>

    <tr>
    <th>Finding</th>
    <th>Severity</th>
    <th>Asset</th>
    <th>Owner</th>
    <th>Source</th>
    <th>Status</th>
    <th>Actions</th>
    <th>Age (days)</th>
    </tr>

    </thead>

    <tbody>

    ${rows}

    </tbody>

    </table>

    <script>

    async function addTestFinding(){

      await fetch("/findings",{
        method:"POST",
        headers:{
          "Content-Type":"application/json"
        },
        body:JSON.stringify({
          title:"Manual test finding",
          severity:"Medium",
          source:"Dashboard",
          asset:"Test Server",
          owner:"Security Team"
        })
      });

      location.reload();

    }

async function uploadCSV(){

  const file = document.getElementById("csvFile").files[0];

  const text = await file.text();

  await fetch("/import-csv",{
    method:"POST",
    body:text
  });

  location.reload();

}

    async function updateStatus(id,status){

      await fetch("/update-status",{
        method:"POST",
        headers:{
          "Content-Type":"application/json"
        },
        body:JSON.stringify({
          id:id,
          status:status
        })
      });

      location.reload();

    }

    </script>

    </body>

    </html>
    `;

    return new Response(html,{
      headers:{ "content-type":"text/html" }
    });

  },
};
