export default {
  async fetch(request, env) {

    const url = new URL(request.url);

    if (url.pathname === "/findings") {

      const { results } = await env.DB.prepare(
        "SELECT title, severity, source, status, age_days FROM findings ORDER BY age_days DESC"
      ).all();

      return Response.json({
        total_findings: results.length,
        findings: results
      });

    }

    // Dashboard page
    const { results } = await env.DB.prepare(
      "SELECT title, severity, source, status, age_days FROM findings ORDER BY age_days DESC"
    ).all();

    const rows = results.map(f => `
      <tr>
        <td>${f.title}</td>
        <td>${f.severity}</td>
        <td>${f.source}</td>
        <td>${f.status}</td>
        <td>${f.age_days}</td>
      </tr>
    `).join("");

    const html = `
    <html>
    <head>
      <title>Security Assurance Dashboard</title>
      <style>
        body {
          font-family: Arial;
          background:#0f172a;
          color:white;
          padding:40px;
        }
        h1 {
          margin-bottom:20px;
        }
        table {
          border-collapse: collapse;
          width:100%;
          background:#1e293b;
        }
        th, td {
          padding:12px;
          border-bottom:1px solid #334155;
        }
        th {
          text-align:left;
          background:#020617;
        }
        tr:hover {
          background:#334155;
        }
      </style>
    </head>

    <body>

      <h1>Security Assurance Dashboard</h1>

      <table>
        <thead>
          <tr>
            <th>Finding</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Status</th>
            <th>Age (days)</th>
          </tr>
        </thead>

        <tbody>
          ${rows}
        </tbody>

      </table>

    </body>
    </html>
    `;

    return new Response(html, {
      headers: { "content-type": "text/html" }
    });

  },
};
