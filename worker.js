export default {
  async fetch(request, env) {

    const url = new URL(request.url);

if (request.method === "POST" && url.pathname === "/import-csv") {

  const csv = await request.text();
  const rows = csv.split("\n").slice(1);

  for (const row of rows) {

    if (!row.trim()) continue;

    const [
      cvss,
      plugin_id,
      name,
      exploit_maturity,
      vpr,
      kev,
      first_seen,
      asset,
      port,
      severity
    ] = row.split(",");

    await env.DB.prepare(
      `INSERT INTO findings
      (title,severity,source,status,created_at,asset,port,cvss,vpr,kev,exploit_maturity,first_seen)
      VALUES (?, ?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      name,
      severity,
      "Tenable",
      "Open",
      asset,
      port,
      cvss,
      vpr,
      kev === "true",
      exploit_maturity,
      first_seen
    )
    .run();
  }

  return Response.json({ message: "CSV imported" });
}

    /* ------------------------------
       CREATE FINDING
    ------------------------------ */

    if (request.method === "POST" && url.pathname === "/findings") {

      const data = await request.json();

      await env.DB.prepare(
        "INSERT INTO findings (title, severity, source, status, created_at, asset, owner) VALUES (?, ?, ?, ?, datetime('now'), ?, ?)"
      )
      .bind(
        data.title,
        data.severity,
        data.source,
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
