"""
Cloud Least Privilege Enforcer - Multi-page Dashboard
Place in the SAME folder as pipeline.py.

    pip install -U streamlit boto3 pandas pyyaml
    streamlit run dashboard.py

pipeline.py and all modules are NOT modified. The dashboard runs
`python pipeline.py` exactly like the CLI (in a background thread), passing the
AWS details via environment variables, then stores every feature's result
separately in <project>/dashboard_scans/<scan-id>/scan.json.
Credentials are never written to disk.
"""
import glob
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime

import boto3
import pandas as pd
import streamlit as st

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

DEFAULT_DIR = os.path.dirname(os.path.abspath(__file__))

# group -> feature -> report files (relative to reports/)
GROUPS = {
    "Discovery": {
        "IAM Scanner": ["policies.json"],
        "CloudTrail Collector": ["cloudtrail_logs.json"],
        "CloudTrail Analyzer": ["usage_report.json"],
        "CloudTrail Behavioral Analysis": ["cloudtrail_analysis.json"],
        "Action Mapper": ["observed_actions.json"],
        "Identity Classification": ["identity_report.json"],
        "Orphan Detection": ["orphan_report.json"],
        "Temporal Analysis": ["temporal_report.json"],
    },
    "Risk Analysis": {
        "Permission Analysis": ["permission_analysis.json"],
        "Risk Scoring": ["risk_report.json"],
        "XGBoost Risk Prediction": ["ml_risk_predictions.json"],
    },
    "Recommendation & Validation": {
        "AI Policy Recommendation": ["ai_recommended_policies.json"],
        "Policy Validation": ["policy_validation_report.json"],
        "IAM Policy Simulation": ["ai_policy_simulation_report.json"],
        "Verification Controller": ["verification_controller_report.json"],
        "Decision Engine": ["decision_engine_report.json"],
    },
    "Deployment": {
        "Rollback Controller": ["rollback/*.json"],
        "Rollback Verification": [],
        "Deployment Review": ["deployment_review_report.json"],
        "Deployment Controller": ["deployment_controller_report.json"],
        "Post-Deployment Verification": ["post_deployment_verification_report.json"],
    },
}
FEATURES = {n: r for g in GROUPS.values() for n, r in g.items()}

ICON = {"pending": "⏳", "running": "🔄", "done": "✅", "failed": "❌", "warn": "⚠️"}
COLOR = {"pending": "#64748b", "running": "#2563eb", "done": "#16a34a",
         "failed": "#dc2626", "warn": "#d97706"}

st.set_page_config(page_title="Cloud Least Privilege Enforcer", page_icon="🔐", layout="wide")
st.markdown("""
<style>
.chip-grid{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 14px}
.chip{padding:6px 12px;border-radius:999px;font-size:13px;color:#fff;white-space:nowrap}
.card{border:1px solid rgba(128,128,128,.3);border-radius:12px;padding:14px 18px}
.card h4{margin:0;font-size:13px;opacity:.7;font-weight:500}
.card p{margin:4px 0 0;font-size:28px;font-weight:700}
.badge{padding:3px 10px;border-radius:6px;color:#fff;font-weight:600;font-size:13px}
</style>""", unsafe_allow_html=True)


# ───────────────────────── data helpers (no streamlit calls) ─────────────────────────
def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def split_log(log):
    log = re.split(r"={70}\s*\n\s*PIPELINE SUMMARY", log)[0]
    parts = re.split(r"={70}\n([^\n=][^\n]*)\n={70}\nRunning:", log)
    return {parts[i].strip(): ("Running:" + parts[i + 1]).strip()
            for i in range(1, len(parts) - 1, 2)}


def build_scan(project_dir, account, arn, log, returncode):
    sections = split_log(log)
    status = {n: s for s, n in re.findall(r"^\[(PASS|FAIL)\]\s+(.+)$", log, flags=re.M)}
    stages = {}
    for name, patterns in FEATURES.items():
        out = sections.get(name, "")
        reports = {}
        for pat in patterns:
            for p in sorted(glob.glob(os.path.join(project_dir, "reports", pat))):
                reports[os.path.basename(p)] = read_json(p)
        stages[name] = {
            "status": status.get(name, "N/A"),
            "warning": bool(re.search(r"CONTROLLER ERROR|Traceback|Error:", out)),
            "output": out,
            "reports": reports,
        }
    now = datetime.now()
    return {"id": now.strftime("%Y%m%d_%H%M%S"), "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "account": account, "arn": arn, "returncode": returncode,
            "stages": stages, "full_log": log}


def save_scan(project_dir, scan):
    folder = os.path.join(project_dir, "dashboard_scans", scan["id"])
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "scan.json"), "w", encoding="utf-8") as f:
        json.dump(scan, f, indent=2, default=str)


def list_saved(project_dir):
    files = glob.glob(os.path.join(project_dir, "dashboard_scans", "*", "scan.json"))
    return sorted((os.path.basename(os.path.dirname(f)) for f in files), reverse=True)


def plain(data):
    return json.loads(json.dumps(data, default=str))


def to_json(data):
    return json.dumps(plain(data), indent=2, ensure_ascii=False)


def to_yaml(data):
    if yaml is None:
        return "# PyYAML not installed. Run: pip install pyyaml\n"
    return yaml.safe_dump(plain(data), sort_keys=False, allow_unicode=True, default_flow_style=False)


def final_report(scan, include_output=False):
    feats = {}
    for name, s in scan["stages"].items():
        item = {"status": s["status"], "warning": s["warning"], "reports": s["reports"]}
        if include_output:
            item["console_output"] = s["output"]
        feats[name] = item
    passed = sum(1 for s in scan["stages"].values() if s["status"] == "PASS")
    return {
        "scan": {"id": scan["id"], "time": scan["time"], "account": scan["account"],
                 "arn": scan["arn"], "exit_code": scan["returncode"]},
        "summary": {"features_total": len(scan["stages"]), "features_passed": passed,
                    "features_with_warnings": [n for n, s in scan["stages"].items() if s["warning"]]},
        "features": feats,
    }


# ───────────────────────── background pipeline job ─────────────────────────
@st.cache_resource
def job_store():
    return {"job": None}


def _worker(job, project_dir, env, account, arn, clear_old):
    try:
        if clear_old:
            for f in glob.glob(os.path.join(project_dir, "reports", "**", "*.json"), recursive=True):
                try:
                    os.remove(f)
                except OSError:
                    pass
        child = {**os.environ, **env, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
        child.pop("AWS_PROFILE", None)
        child.pop("AWS_SESSION_TOKEN", None)
        proc = subprocess.Popen(
            [sys.executable, "-u", "pipeline.py"], cwd=project_dir, env=child,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace")
        prev = ""
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            job["lines"].append(line)
            s = line.strip()
            if s == "Running:" and prev in job["stages"]:
                job["stages"][prev] = "running"
                job["current"] = prev
            m = re.match(r"^(.+) : COMPLETED$", s)
            if m and m.group(1) in job["stages"]:
                job["stages"][m.group(1)] = "done"
            if s and not set(s) <= {"="}:
                prev = s
        proc.wait()
        log = "\n".join(job["lines"])
        scan = build_scan(project_dir, account, arn, log, proc.returncode)
        for n, st_ in scan["stages"].items():
            job["stages"][n] = ("warn" if st_["warning"] else
                                "failed" if st_["status"] == "FAIL" else "done")
        save_scan(project_dir, scan)
        job["scan"] = scan
        job["returncode"] = proc.returncode
    except Exception as e:  # keep the UI informed instead of dying silently
        job["error"] = str(e)
    finally:
        job["ended"] = datetime.now()
        job["running"] = False


def start_job(project_dir, env, account, arn, clear_old):
    job = {"running": True, "stages": {n: "pending" for n in FEATURES}, "lines": [],
           "current": "", "returncode": None, "scan": None, "error": None,
           "started": datetime.now(), "ended": None}
    job_store()["job"] = job
    st.session_state.pop("scan", None)
    threading.Thread(target=_worker, args=(job, project_dir, env, account, arn, clear_old),
                     daemon=True).start()


def current_scan():
    if st.session_state.get("scan"):
        return st.session_state.scan
    job = job_store()["job"]
    return job["scan"] if job and job.get("scan") else None


# ───────────────────────── ui helpers ─────────────────────────
def card(col, title, value):
    col.markdown(f'<div class="card"><h4>{title}</h4><p>{value}</p></div>', unsafe_allow_html=True)


def chips(stages):
    html = "".join(f'<span class="chip" style="background:{COLOR[s]}">{ICON[s]} {n}</span>'
                   for n, s in stages.items())
    st.markdown(f'<div class="chip-grid">{html}</div>', unsafe_allow_html=True)


def records_of(data):
    if isinstance(data, list) and data and all(isinstance(x, dict) for x in data):
        return data
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return v
    return None


def render(data):
    if data is None:
        st.info("No data.")
        return
    rec = records_of(data)
    if rec:
        try:
            st.dataframe(pd.json_normalize(rec), use_container_width=True)
        except Exception:
            pass
    with st.expander("Raw JSON", expanded=rec is None):
        st.json(data)


def export_buttons(data, base, key):
    c1, c2, _ = st.columns([1, 1, 3])
    c1.download_button("⬇ Download JSON", to_json(data), f"{base}.json", "application/json",
                       key=f"{key}_j", use_container_width=True)
    c2.download_button("⬇ Download YAML", to_yaml(data), f"{base}.yaml", "text/yaml",
                       key=f"{key}_y", use_container_width=True)


def need_scan():
    st.info("No scan results yet. Go to **Run Pipeline** to start a scan, or open one from **History**.")
    st.page_link(pipeline_page, label="Go to Run Pipeline", icon="▶️")


# ───────────────────────── pages ─────────────────────────
def page_connect():
    st.title("🔌 Connect AWS Account")
    st.session_state.setdefault("project_dir", DEFAULT_DIR)
    st.session_state.project_dir = st.text_input("Project folder (contains pipeline.py)",
                                                 st.session_state.project_dir)
    if not os.path.isfile(os.path.join(st.session_state.project_dir, "pipeline.py")):
        st.error("pipeline.py not found in this folder.")

    if "env" in st.session_state:
        st.success(f"Connected · Account **{st.session_state.account}** · `{st.session_state.arn}`")
        if st.button("Disconnect"):
            for k in ("env", "account", "arn"):
                st.session_state.pop(k, None)
            st.rerun()
        st.page_link(pipeline_page, label="Continue to Run Pipeline", icon="▶️")
        return

    st.caption("Credentials stay in memory and are passed only to the pipeline process. Nothing is saved to disk.")
    with st.form("aws"):
        region = st.text_input("Region", "ap-south-1")
        ak = st.text_input("Access Key ID")
        sk = st.text_input("Secret Access Key", type="password")
        go = st.form_submit_button("Verify & connect", type="primary")
    if go:
        if not ak or not sk:
            st.error("Access Key ID and Secret Access Key are required.")
            return
        try:
            s = boto3.Session(aws_access_key_id=ak.strip(), aws_secret_access_key=sk.strip(),
                              region_name=region.strip())
            who = s.client("sts").get_caller_identity()
            st.session_state.env = {"AWS_ACCESS_KEY_ID": ak.strip(), "AWS_SECRET_ACCESS_KEY": sk.strip(),
                                    "AWS_DEFAULT_REGION": region.strip(), "AWS_REGION": region.strip()}
            st.session_state.account, st.session_state.arn = who["Account"], who["Arn"]
            st.rerun()
        except Exception as e:
            st.error(f"Authentication failed: {e}")


def page_pipeline():
    st.title("▶️ Run Pipeline")
    job = job_store()["job"]

    # ---- progress at the TOP ----
    if job:
        stages = job["stages"]
        done = sum(1 for v in stages.values() if v in ("done", "failed", "warn"))
        total = len(stages)
        end = job["ended"] or datetime.now()
        elapsed = int((end - job["started"]).total_seconds())
        st.progress(done / total, text=f"{done}/{total} features complete"
                    + (f" · now running: {job['current']}" if job["running"] else ""))
        c = st.columns(4)
        card(c[0], "Completed", f"{done}/{total}")
        card(c[1], "Running", job["current"] if job["running"] else "—")
        card(c[2], "Elapsed", f"{elapsed // 60}m {elapsed % 60}s")
        card(c[3], "State", "Running…" if job["running"] else ("Error" if job["error"] else "Finished"))
        st.write("")
        chips(stages)
    else:
        st.caption("No run yet. Progress of each feature will appear here once you start.")
        chips({n: "pending" for n in FEATURES})

    # ---- controls ----
    running = bool(job and job["running"])
    connected = "env" in st.session_state
    if not connected and not running:
        st.warning("Connect an AWS account first.")
        st.page_link(connect_page, label="Go to Connect AWS Account", icon="🔌")
    else:
        clear_old = st.checkbox("Clear previous pipeline reports before running", value=True,
                                disabled=running, help="Results stay saved in dashboard_scans/.")
        if st.button("▶ Run full pipeline", type="primary", disabled=running or not connected):
            start_job(st.session_state.project_dir, st.session_state.env,
                      st.session_state.account, st.session_state.arn, clear_old)
            st.rerun()

    # ---- results / log ----
    if job:
        if job["error"]:
            st.error(f"Pipeline runner error: {job['error']}")
        if job["scan"]:
            scan = job["scan"]
            (st.error if scan["returncode"] else st.success)(
                "Pipeline finished" + (f" with exit code {scan['returncode']}" if scan["returncode"] else " successfully")
                + ". Open any feature page from the sidebar to see its result.")
            st.subheader("Final output")
            export_buttons(final_report(scan), f"least_privilege_report_{scan['id']}", "final")
        with st.expander("Live console output", expanded=running):
            st.code("\n".join(job["lines"][-60:]) or "Starting…", language="text")
    if running:
        time.sleep(1)
        st.rerun()


def page_overview():
    st.title("📊 Dashboard")
    scan = current_scan()
    if not scan:
        return need_scan()
    st.caption(f"Scan `{scan['id']}` · {scan['time']} · Account {scan['account']}")
    stages = scan["stages"]
    passed = sum(1 for s in stages.values() if s["status"] == "PASS")
    warns = sum(1 for s in stages.values() if s["warning"])

    risk = None
    for data in stages["Risk Scoring"]["reports"].values():
        risk = records_of(data)
    df = pd.json_normalize(risk) if risk else None
    name_c = score_c = level_c = None
    if df is not None:
        cols = {c.lower(): c for c in df.columns}
        name_c = next((cols[c] for c in cols if c in ("identity", "user", "name", "identity_name")), None)
        score_c = next((cols[c] for c in cols if "total" in c and "risk" in c), None)
        level_c = next((cols[c] for c in cols if "level" in c), None)

    c = st.columns(4)
    card(c[0], "Features passed", f"{passed}/{len(stages)}")
    card(c[1], "Warnings", warns)
    card(c[2], "Identities scored", len(df) if df is not None else "—")
    high = int((df[level_c].astype(str).str.lower() == "high").sum()) if df is not None and level_c else "—"
    card(c[3], "High-risk identities", high)

    st.write("")
    m = re.search(r"DECISION:\s*(\S+)", stages["Decision Engine"]["output"])
    if m:
        st.markdown(f"**Decision engine:** <span class='badge' style='background:#2563eb'>{m.group(1)}</span>",
                    unsafe_allow_html=True)
    if df is not None and name_c and score_c:
        st.subheader("Risk score by identity")
        st.bar_chart(df.set_index(name_c)[score_c])

    st.subheader("Feature status")
    chips({n: ("warn" if s["warning"] else "failed" if s["status"] == "FAIL" else "done")
           for n, s in stages.items()})
    st.subheader("Final output")
    inc = st.checkbox("Include console output in export", value=False)
    export_buttons(final_report(scan, inc), f"least_privilege_report_{scan['id']}", "ov")


def make_feature_page(name):
    def page():
        st.title(name)
        scan = current_scan()
        if not scan:
            return need_scan()
        s = scan["stages"][name]
        stt = "warn" if s["warning"] else "failed" if s["status"] == "FAIL" else "done"
        st.markdown(f"<span class='badge' style='background:{COLOR[stt]}'>{ICON[stt]} "
                    f"{s['status'] if not s['warning'] else 'ERROR IN OUTPUT'}</span> "
                    f"&nbsp; Scan `{scan['id']}`", unsafe_allow_html=True)
        if s["warning"]:
            st.warning("An error message appears in this feature's console output.")
        t1, t2, t3 = st.tabs(["Report", "Console output", "Export"])
        with t1:
            if not s["reports"]:
                st.info("This feature produces no report file. See Console output.")
            for fname, data in s["reports"].items():
                st.subheader(fname)
                render(data)
        with t2:
            st.code(s["output"] or "No console output captured.", language="text")
        with t3:
            export_buttons({"feature": name, "status": s["status"], "reports": s["reports"],
                            "console_output": s["output"]},
                           name.lower().replace(" ", "_").replace("-", "_"), f"f_{name}")
    return page


def page_history():
    st.title("🗂 History")
    saved = list_saved(st.session_state.get("project_dir", DEFAULT_DIR))
    if not saved:
        st.info("No saved scans yet.")
        return
    pick = st.selectbox("Saved scans", saved)
    if st.button("Open this scan", type="primary"):
        st.session_state.scan = read_json(os.path.join(
            st.session_state.get("project_dir", DEFAULT_DIR), "dashboard_scans", pick, "scan.json"))
        st.success("Scan loaded. Open the Dashboard or any feature page.")


def page_downloads():
    st.title("⬇ Downloads")
    scan = current_scan()
    if not scan:
        return need_scan()
    inc = st.checkbox("Include console output of each feature", value=False)
    rep = final_report(scan, inc)
    st.markdown("**Final report (all features)**")
    export_buttons(rep, f"least_privilege_report_{scan['id']}", "dl_all")
    with st.expander("Preview (YAML)"):
        st.code(to_yaml(rep)[:6000], language="yaml")
    st.markdown("**Per-feature files**")
    for name, s in scan["stages"].items():
        with st.expander(name):
            export_buttons({"feature": name, "status": s["status"], "reports": s["reports"]},
                           name.lower().replace(" ", "_").replace("-", "_"), f"dl_{name}")


# ───────────────────────── navigation ─────────────────────────
connect_page = st.Page(page_connect, title="Connect AWS Account", icon="🔌", url_path="connect")
pipeline_page = st.Page(page_pipeline, title="Run Pipeline", icon="▶️", url_path="pipeline")
nav = {
    "Setup": [connect_page, pipeline_page],
    "Overview": [st.Page(page_overview, title="Dashboard", icon="📊", url_path="dashboard")],
}
for group, feats in GROUPS.items():
    nav[group] = [st.Page(make_feature_page(n), title=n, icon="🔹",
                          url_path=re.sub(r"[^a-z0-9]+", "-", n.lower()).strip("-"))
                  for n in feats]
nav["Results"] = [st.Page(page_downloads, title="Downloads", icon="⬇", url_path="downloads"),
                  st.Page(page_history, title="History", icon="🗂", url_path="history")]

with st.sidebar:
    st.markdown("### 🔐 Least Privilege Enforcer")
    if "env" in st.session_state:
        st.caption(f"Connected: {st.session_state.account}")
    else:
        st.caption("Not connected")

st.navigation(nav).run()
