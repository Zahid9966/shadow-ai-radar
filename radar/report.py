"""Self-contained HTML report (no JS, no external assets, inline SVG). interactive=True adds triage forms for `radar serve`."""
import html

COLORS = {"critical": "#b42318", "high": "#d9480f", "medium": "#b7791f", "low": "#2f6f4e"}
STATUSES = ("open", "ack", "resolved", "false_positive")


def _bars(pairs, w=520, h=18):
    mx = max((v for _, v in pairs), default=1) or 1
    rows = "".join(
        f'<text x="0" y="{i * (h + 6) + 13}" font-size="12">{html.escape(str(k))}</text>'
        f'<rect x="170" y="{i * (h + 6)}" width="{max(2, int((w - 230) * v / mx))}" height="{h}" fill="#2b6cb0" rx="3"/>'
        f'<text x="{175 + int((w - 230) * v / mx)}" y="{i * (h + 6) + 13}" font-size="11">{v:,.0f}</text>'
        for i, (k, v) in enumerate(pairs))
    return f'<svg width="{w}" height="{len(pairs) * (h + 6)}">{rows}</svg>'


def _status_cell(a, interactive):
    e = html.escape
    if not interactive:
        return e(a["status"])
    opts = "".join(f'<option{" selected" if s == a["status"] else ""}>{s}</option>' for s in STATUSES)
    return (f'<form method=post action="/alerts/{e(a["alert_id"])}"><select name=status>{opts}</select>'
            f'<input name=note placeholder="note" value="{e(a["note"] or "")}" size=14><button>save</button></form>')


def render(db, alerts, path=None, interactive=False):
    e = html.escape
    kpi = db.execute("SELECT COUNT(*), COUNT(DISTINCT user), ROUND(100.0*SUM(status!='sanctioned')/COUNT(*),1) "
                     "FROM silver_events WHERE is_ai=1").fetchone()
    rejected = db.execute("SELECT COUNT(*) FROM dq_rejects").fetchone()[0]
    svc = db.execute("SELECT service,status,events,users,risk FROM gold_service ORDER BY risk DESC").fetchall()
    dept = db.execute("SELECT dept,ai_events,pct_unsanctioned,risk FROM gold_dept ORDER BY risk DESC").fetchall()
    daily = db.execute("SELECT day, SUM(risk) FROM gold_user_day GROUP BY day ORDER BY day").fetchall()
    users = db.execute("SELECT user,dept,ai_events,unsanctioned,leaks,risk FROM gold_user ORDER BY risk DESC LIMIT 8").fetchall()
    weeks = db.execute("SELECT week,days,ai_events,users,pct_unsanctioned,leaks,ROUND(risk/days,1) FROM gold_week ORDER BY week").fetchall()
    trows = ""
    for i, (wk, days, ev, us, pu, lk, rpd) in enumerate(weeks):
        if i:
            prev = weeks[i - 1][6] or 0
            ch = (rpd - prev) / prev * 100 if prev else 0
            delta = f'<b style="color:{"#b42318" if ch > 10 else "#2f6f4e" if ch < -10 else "inherit"}">{"▲" if ch > 0 else "▼"} {abs(ch):.0f}%</b>'
        else:
            delta = "—"
        trows += f"<tr><td>{e(wk)}</td><td>{days}</td><td>{ev:,}</td><td>{us}</td><td>{pu}%</td><td>{lk}</td><td>{rpd:,.0f}</td><td>{delta}</td></tr>"
    n_open = sum(a["status"] in ("open", "ack") for a in alerts)
    arows = "".join(
        f'<tr style="{"opacity:.5" if a["status"] in ("resolved", "false_positive") else ""}">'
        f'<td><b style="color:{COLORS[a["severity"]]}">{a["severity"].upper()}</b></td><td>{e(a["kind"])}<br><small>{e(a["alert_id"])}</small></td>'
        f'<td>{e(a["day"])}</td><td>{e(a["user"] or "—")}{("<br><small>mgr: " + e(a["manager"]) + "</small>") if a.get("manager") else ""}</td><td>{e(a["title"])}'
        f'{" ×%d" % a["count"] if a["count"] > 1 else ""}<br><small>{e(str(a["evidence"]))}</small></td>'
        f'<td><small>{e(a["action"])}</small></td><td>{_status_cell(a, interactive)}</td></tr>' for a in alerts)
    srows = "".join(f"<tr><td>{e(s)}</td><td>{e(st)}</td><td>{ev}</td><td>{u}</td><td>{r:,.0f}</td></tr>" for s, st, ev, u, r in svc)
    urows = "".join(f"<tr><td>{e(u)}</td><td>{e(d)}</td><td>{n}</td><td>{x}</td><td>{l}</td><td>{r:,.0f}</td></tr>" for u, d, n, x, l, r in users)
    page = f"""<!doctype html><meta charset=utf-8><title>Shadow-AI Radar</title>
<style>body{{font:14px system-ui;margin:2rem auto;max-width:1150px;color:#1a202c}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}}.k{{display:inline-block;margin:0 2rem 1rem 0}}
.k b{{font-size:28px;display:block}}h2{{margin-top:2rem}}form{{display:flex;gap:4px}}</style>
<h1>Shadow-AI Radar</h1>
<div class=k><b>{kpi[0]:,}</b>AI requests</div><div class=k><b>{kpi[1]}</b>employees using AI</div>
<div class=k><b>{"—" if kpi[2] is None else str(kpi[2]) + "%"}</b>on unsanctioned tools</div><div class=k><b>{n_open}</b>open alerts</div>
<div class=k><b>{rejected}</b>log lines rejected by DQ</div>
<h2>Alerts</h2><table><tr><th>Sev</th><th>Type / ID</th><th>Day</th><th>User</th><th>Finding</th><th>Recommended action</th><th>Status</th></tr>{arows}</table>
<h2>Highest-risk users (for coaching, not punishment)</h2><table><tr><th>User</th><th>Dept</th><th>AI requests</th><th>Unsanctioned</th><th>Leaks</th><th>Risk</th></tr>{urows}</table>
<h2>Week-over-week trend</h2><table><tr><th>Week of</th><th>Active days</th><th>AI requests</th><th>Users</th><th>% unsanctioned</th><th>Leaks</th><th>Risk / day</th><th>Δ risk/day</th></tr>{trows}</table>
<p><small>Risk is normalised per active day so a partial week is not misread as an improvement. Few weeks of data = weak trend: treat it as a signal, not a verdict.</small></p>
{_bars([(w[0], w[6]) for w in weeks]) if weeks else ""}
<h2>Risk by day</h2>{_bars(daily)}
<h2>Risk by department</h2>{_bars([(d, r) for d, _, _, r in dept])}
<h2>AI services</h2><table><tr><th>Service</th><th>Policy</th><th>Events</th><th>Users</th><th>Risk</th></tr>{srows}</table>
<p><small>Content-category risk uses a bootstrap classifier at reduced weight until you train one on real labels (<code>radar train</code>); secret/PII detection does not depend on it. Prompts are redacted before storage; raw secrets and PII never reach the database or this report.</small></p>"""
    if path:
        open(path, "w").write(page)
    return page
