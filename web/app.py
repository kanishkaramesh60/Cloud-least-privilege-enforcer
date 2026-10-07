from flask import Flask, render_template, jsonify
import os
import subprocess
import sys
import threading
import uuid
import json
from datetime import datetime

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

pipeline_process = None
pipeline_output = []
pipeline_running = False
pipeline_status = "IDLE"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "application": "LeastPrivForge"
    })


@app.route("/api/status")
def status():
    return jsonify({
        "status": pipeline_status,
        "running": pipeline_running,
        "output": pipeline_output[-100:]
    })


def run_pipeline():
    global pipeline_process
    global pipeline_output
    global pipeline_running
    global pipeline_status

    pipeline_output = []
    pipeline_running = True
    pipeline_status = "RUNNING"

    env = os.environ.copy()

    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["LEAST_PRIVILEGE_DASHBOARD"] = "1"

    try:
        pipeline_process = subprocess.Popen(
            [sys.executable, "pipeline.py"],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env
        )

        for line in pipeline_process.stdout:
            line = line.rstrip()
            if line:
                pipeline_output.append(line)

        return_code = pipeline_process.wait()

        if return_code == 0:
            pipeline_status = "COMPLETED"
        else:
            pipeline_status = "FAILED"

    except Exception as e:
        pipeline_output.append(f"ERROR: {e}")
        pipeline_status = "FAILED"

    finally:
        pipeline_running = False
        pipeline_process = None


@app.route("/api/start", methods=["POST"])
def start_pipeline():
    global pipeline_running

    if pipeline_running:
        return jsonify({
            "success": False,
            "message": "Pipeline is already running"
        })

    thread = threading.Thread(
        target=run_pipeline,
        daemon=True
    )

    thread.start()

    return jsonify({
        "success": True,
        "message": "LeastPrivForge pipeline started"
    })


@app.route("/api/stop", methods=["POST"])
def stop_pipeline():
    global pipeline_process
    global pipeline_running
    global pipeline_status

    if pipeline_process and pipeline_running:
        pipeline_process.terminate()

        pipeline_running = False
        pipeline_status = "STOPPED"

        return jsonify({
            "success": True,
            "message": "Pipeline stopped"
        })

    return jsonify({
        "success": False,
        "message": "No pipeline is currently running"
    })


@app.route("/api/reports")
def reports():

    reports_dir = os.path.join(BASE_DIR, "reports")

    if not os.path.exists(reports_dir):
        return jsonify([])

    files = []

    for filename in os.listdir(reports_dir):

        filepath = os.path.join(
            reports_dir,
            filename
        )

        if os.path.isfile(filepath):

            files.append({
                "name": filename,
                "size": os.path.getsize(filepath)
            })

    return jsonify(files)


@app.route("/api/report/<filename>")
def report(filename):

    reports_dir = os.path.join(BASE_DIR, "reports")

    filepath = os.path.join(
        reports_dir,
        filename
    )

    if not os.path.exists(filepath):
        return jsonify({
            "error": "Report not found"
        }), 404

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        return jsonify(data)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )