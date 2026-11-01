"""Research-portal shell using the user's existing black/green SOC palette.

The body is developer-owned canned HTML, never unescaped participant input.
"""
SHELL = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Workspace · DeceptionGraph Research Portal</title><style>
:root{{color-scheme:dark;--navy:#050505;--teal:#39ff88;--ink:#f4f4f2;--muted:#a6a6a3;--line:#1f1f1f;--card:#0c0c0c;--raised:#151515}}
*{{box-sizing:border-box}}body{{margin:0;background:#050505;color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
.wrap{{max-width:1120px;margin:auto;padding:0 20px}}header{{background:var(--navy);color:var(--ink);border-bottom:1px solid var(--line)}}
.bar{{min-height:64px;display:flex;align-items:center;gap:26px;flex-wrap:wrap;padding-top:10px;padding-bottom:10px}}
.brand{{font-weight:700;font-size:19px;color:white;text-decoration:none;display:flex;align-items:center;gap:10px}}
.brand span{{font-weight:400;color:var(--muted)}}nav{{display:flex;gap:20px;flex:1}}nav a{{color:var(--ink);text-decoration:none}}
a{{color:var(--teal)}}main{{min-height:70vh;padding-top:32px!important;padding-bottom:32px!important}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px}}h1{{font-size:32px;margin:6px 0 12px}}h2{{font-size:28px;margin-top:0}}h3{{font-size:17px}}
.eyebrow{{color:var(--teal);text-transform:uppercase;font-size:12px;font-weight:700;letter-spacing:.1em}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px}}p,small{{color:var(--muted)}}
input,button{{font:inherit;border:1px solid #2f2f2f;border-radius:6px;padding:10px;margin:6px 0}}input{{max-width:100%;background:var(--raised);color:var(--ink)}}input::placeholder{{color:var(--muted)}}
button,.btn{{background:var(--teal);color:#050505;font-weight:600;border:0;padding:10px 16px;border-radius:6px;text-decoration:none;cursor:pointer}}
:focus-visible{{outline:2px solid var(--teal);outline-offset:3px}}nav a:hover{{color:var(--teal)}}
form:not(.login){{display:flex;flex-wrap:wrap;gap:8px;align-items:center}}input[name=q]{{width:400px}}
form.login{{max-width:400px;margin:16px auto}}form.login input{{display:block;width:100%}}form.login button{{width:100%}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:12px;text-align:left;border-bottom:1px solid var(--line)}}
footer{{background:var(--card);border-top:1px solid var(--line);padding:20px 0;font-size:13px;color:var(--muted)}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
@media(max-width:800px){{.grid{{grid-template-columns:1fr}}nav{{flex-basis:100%}}.brand span{{display:none}}}}
</style><header><div class="wrap bar"><a class="brand" href="/">
<svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true"><rect width="28" height="28" rx="6" fill="#151515"/><path d="M7 8L21 14L8 21" stroke="#39ff88" stroke-width="2" fill="none"/><circle cx="7" cy="8" r="3" fill="#39ff88"/><circle cx="21" cy="14" r="3" fill="#f4f4f2"/><circle cx="8" cy="21" r="3" fill="#39ff88"/></svg>
DeceptionGraph <span>Research Portal</span></a><nav aria-label="Main"><a href="/">Home</a><a href="/reports">Reports</a><a href="/resources">Resources</a><a href="/search">Search</a></nav><a class="btn" href="/login">Sign in</a></div></header>
<main class="wrap"><section class="card">{}</section></main>
<footer><div class="wrap">© 2026 DeceptionGraph Research Portal · Demonstration portal. All people, projects and data are fictional.</div></footer></html>"""

HOME = """<span class="eyebrow">Internal research workspace</span><h1>Research that connects people and ideas.</h1>
<p>Find project reports, shared datasets and resources for your research group.</p>
<form action="/search"><input name="q" placeholder="Search reports and datasets" aria-label="Search reports and datasets"><button>Search</button></form>
<div class="grid"><div><h3>Quick links</h3><p><a href="/reports">Research reports</a></p><p><a href="/resources">Dataset catalogue</a></p></div>
<div><h3>Announcements</h3><p>Quarterly research review · Group data submissions are open.</p><p>Equipment booking schedules have been updated.</p></div></div>"""

REPORTS = """<span class="eyebrow">Research groups</span><h2>Reports</h2><div class="grid">
<div><h3><a href="/reports/coastal-sensor-calibration">Coastal sensor calibration</a></h3><p>Field measurements and instrument calibration.</p></div>
<div><h3><a href="/reports/campus-energy-baseline">Campus energy baseline</a></h3><p>Reference measurements for building energy use.</p></div></div>"""
