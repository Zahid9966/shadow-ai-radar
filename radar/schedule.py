"""Generate (never install) systemd units / cron lines so the tool runs unattended. Installing needs a human decision:
review the files, then copy them yourself. Secrets live in a 0600 EnvironmentFile you create, never in a unit."""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OK = re.compile(r"^[A-Za-z0-9_./+-]+$")  # systemd specifiers (% $) and spaces would need escaping: refuse instead


def _check(*paths):
    for p in paths:
        if not _OK.match(p):
            raise SystemExit(f"path {p!r} has spaces or special characters; use a plain path (systemd quoting is easy to get wrong)")


def generate(out_dir, logs, env_file, system=False, interval=60):
    out_dir, logs, env_file = (os.path.abspath(p) for p in (out_dir, logs, env_file))
    py = sys.executable
    _check(out_dir, logs, env_file, py, ROOT)
    d = os.path.join(out_dir, "schedule")
    os.makedirs(d, mode=0o700, exist_ok=True)
    wanted = "multi-user.target" if system else "default.target"
    base = f"{py} -m radar --out {out_dir}"
    harden = f"""UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={out_dir}
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
"""
    notify = "" if system else " --notify"  # desktop notifications need the user's session bus
    files = {
        "radar-watch.service": f"""[Unit]
Description=Shadow-AI Radar: continuous ingest and detection

[Service]
Type=simple
WorkingDirectory={ROOT}
EnvironmentFile=-{env_file}
ExecStart={base} --logs {logs} watch --interval {int(interval)}{notify}
Restart=on-failure
RestartSec=15
{harden}
[Install]
WantedBy={wanted}
""",
        "radar-weekly.service": f"""[Unit]
Description=Shadow-AI Radar: weekly integrity, backup and evidence run

[Service]
Type=oneshot
WorkingDirectory={ROOT}
EnvironmentFile=-{env_file}
ExecStart={base} audit anchor
ExecStart={base} audit verify --against {out_dir}/audit_anchors.txt
ExecStart={base} backup --to {out_dir}/backup-weekly.enc
ExecStart={base} evidence
# doctor last: a FAIL makes this unit fail, which systemd/journal monitoring will surface
ExecStart={base} doctor
{harden}""",
        "radar-weekly.timer": """[Unit]
Description=Run Shadow-AI Radar weekly checks

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=15min

[Install]
WantedBy=timers.target
""",
        "radar.env.example": """# Copy to a root/owner-only file (chmod 600) and fill in. Generate tokens with:
#   python3 -c "import secrets; print(secrets.token_urlsafe(24))"
RADAR_USERS=alice=analyst:CHANGE_ME_TO_A_LONG_RANDOM_TOKEN;bob=viewer:CHANGE_ME_TO_ANOTHER_LONG_TOKEN
RADAR_PSEUDO_KEY=CHANGE_ME_AT_LEAST_16_CHARS
RADAR_BACKUP_PASSPHRASE=CHANGE_ME_AT_LEAST_12_CHARS
""",
        "crontab.example": f"""# Alternative to systemd. Load secrets from the 0600 env file; run `crontab -e` and paste.
@reboot      set -a; . {env_file}; set +a; cd {ROOT} && {base} --logs {logs} watch --interval {int(interval)} >> {out_dir}/watch.log 2>&1
17 3 * * 0   set -a; . {env_file}; set +a; cd {ROOT} && {base} audit anchor && {base} backup --to {out_dir}/backup-weekly.enc && {base} evidence && {base} doctor
""",
    }
    for name, text in files.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(text)
    inst = "/etc/systemd/system" if system else "~/.config/systemd/user"
    ctl = "systemctl" if system else "systemctl --user"
    with open(os.path.join(d, "INSTALL.txt"), "w") as f:
        f.write(f"""Review every file first. Nothing here has been installed.
1. Create {env_file} from radar.env.example, fill it, then: chmod 600 {env_file}
2. cp radar-watch.service radar-weekly.service radar-weekly.timer {inst}/
3. {ctl} daemon-reload
4. {ctl} enable --now radar-watch.service radar-weekly.timer
5. After ANY restore from backup, run `audit anchor` again (a restore legitimately rolls the log back).
6. Copy {out_dir}/audit_anchors.txt off this machine after each weekly run.
Logs: journalctl {'' if system else '--user '}-u radar-watch
""")
    return d, sorted(files) + ["INSTALL.txt"]
