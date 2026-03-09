export default {
  async fetch(request, env) {

    const url = new URL(request.url);

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
        data.asset || "Unknown",
        data.owner || "Unassigned"
      )
      .run();

      return Response.json({ message: "Finding created" });
    }

    if (url.pathname === "/findings") {

      const { results } = await env.DB.prepare(
        "SELECT title,severity,source,status,asset,owner,CAST((julianday('now') - julianday(created_at)) AS INTEGER) AS age_days FROM findings ORDER BY age_days DESC"
      ).all();

      return Response.json({
        total_findings: results.length,
        findings: results
      });

    }

    const { results } = await env.DB.prepare(
      "SELECT title,severity,source,status,asset,owner,CAST((julianday('now') - julianday(created_at)) AS INTEGER) AS age_days FROM findings ORDER BY age_days DESC"
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

    const rows = results.map(f => {

      let color = "#64748b";

      if (f.severity === "Critical") color = "#ef4444";
      if (f.severity === "High") color = "#f97316";
      if (f.severity === "Medium") color = "#eab308";
      if (f.severity === "Low") color = "#22c55e";

      return `
        <tr>
          <td>${f.title}</td>
          <td><span style="color:${color}; font-weight:bold">${f.severity}</span></td>
          <td>${f.asset}</td>
          <td>${f.owner}</td>
          <td>${f.source}</td>
          <td>${f.status}</td>
          <td>${f.age_days}</td>
        </tr>
      `;

    }).join("");

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
          text-align:left;
          background:#020617;
        }

        tr:hover{
          background:#334155;
        }

      </style>

    </head>

    <body>

      <div style="display:flex;gap:20px;margin-bottom:30px">

        <div style="background:#7f1d1d;padding:15px;border-radius:6px">
        Critical: ${critical}
        </div>

        <div style="background:#9a3412;padding:15px;border-radius:6px">
        High: ${high}
        </div>

        <div style="background:#854d0e;padding:15px;border-radius:6px">
        Medium: ${medium}
        </div>

        <div style="background:#14532d;padding:15px;border-radius:6px">
        Low: ${low}
        </div>

      </div>

      <h1>Security Assurance Dashboard</h1>

      <button onclick="addTestFinding()" style="margin-bottom:20px;padding:10px 15px;background:#2563eb;color:white;border:none;border-radius:5px;cursor:pointer">
      Add Test Finding
      </button>

      <table>

        <thead>
          <tr>
            <th>Finding</th>
            <th>Severity</th>
            <th>Asset</th>
            <th>Owner</th>
            <th>Source</th>
            <th>Status</th>
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

</script>

    </body>
    </html>
    `;

    return new Response(html,{
      headers:{ "content-type":"text/html" }
    });

  },
};