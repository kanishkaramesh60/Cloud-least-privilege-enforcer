from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
controller = PROJECT_ROOT / "validation" / "deployment_controller.py"

if not controller.exists():
    raise SystemExit(f"ERROR: {controller} not found.")

text = controller.read_text(encoding="utf-8")

if "import os\\n" not in text:
    text = text.replace(
        "from datetime import datetime, timezone\\n",
        "from datetime import datetime, timezone\\nimport os\\nimport time\\n",
        1,
    )
elif "import time\\n" not in text:
    text = text.replace("import os\\n", "import os\\nimport time\\n", 1)

start = text.find("def request_approval(")
if start < 0:
    raise SystemExit("ERROR: Could not find request_approval().")

end = text.find("\n# ============================================================", start)
if end < 0:
    raise SystemExit("ERROR: Could not determine the end of request_approval().")

new_function = 'def request_approval(\n    identity,\n    actions\n):\n\n    print()\n\n    print(\n        "=" * 65\n    )\n\n    print(\n        "                 HUMAN DEPLOYMENT APPROVAL"\n    )\n\n    print(\n        "=" * 65\n    )\n\n    print()\n\n    print(\n        "Target Identity :",\n        identity\n    )\n\n    print(\n        "Deployment Mode :",\n        "DRY RUN"\n        if DRY_RUN\n        else "LIVE"\n    )\n\n    print()\n\n    print(\n        "Policy Actions:"\n    )\n\n    print(\n        "-" * 65\n    )\n\n    for action in actions:\n\n        print(\n            " -",\n            action\n        )\n\n    print()\n\n    if DRY_RUN:\n\n        print(\n            "No AWS changes will be made during DRY RUN."\n        )\n\n    else:\n\n        print(\n            "WARNING: LIVE AWS changes are enabled."\n        )\n\n        print(\n            "The target IAM user\'s policies may be modified."\n        )\n\n    print()\n\n    # --------------------------------------------------------\n    # DASHBOARD APPROVAL MODE\n    #\n    # A browser cannot answer Python input(). When the pipeline\n    # is launched by the dashboard, wait for the dashboard to\n    # write APPROVE or CANCEL to the approval file.\n    #\n    # Normal CMD execution is unchanged and still uses input().\n    # --------------------------------------------------------\n\n    dashboard_mode = (\n        os.environ.get(\n            "LEAST_PRIVILEGE_DASHBOARD",\n            ""\n        )\n        == "1"\n    )\n\n    if dashboard_mode:\n\n        approval_file = Path(\n            os.environ.get(\n                "LEAST_PRIVILEGE_APPROVAL_FILE",\n                str(\n                    BASE_DIR\n                    / "reports"\n                    / ".dashboard_approval"\n                )\n            )\n        )\n\n        print(\n            "Waiting for dashboard human approval..."\n        )\n\n        print(\n            "Approve or cancel from the dashboard."\n        )\n\n        while True:\n\n            try:\n\n                if approval_file.exists():\n\n                    decision = (\n                        approval_file\n                        .read_text(\n                            encoding="utf-8"\n                        )\n                        .strip()\n                        .upper()\n                    )\n\n                    if decision == "APPROVE":\n\n                        print(\n                            "Dashboard approval received: APPROVE"\n                        )\n\n                        try:\n                            approval_file.unlink()\n                        except FileNotFoundError:\n                            pass\n\n                        return True\n\n                    if decision == "CANCEL":\n\n                        print(\n                            "Dashboard approval received: CANCEL"\n                        )\n\n                        try:\n                            approval_file.unlink()\n                        except FileNotFoundError:\n                            pass\n\n                        return False\n\n            except OSError as error:\n\n                print(\n                    "Approval channel error:",\n                    str(error)\n                )\n\n            time.sleep(0.5)\n\n    # --------------------------------------------------------\n    # NORMAL CMD MODE\n    # --------------------------------------------------------\n\n    response = input(\n        "Type APPROVE to continue or anything else to cancel: "\n    ).strip()\n\n    return response == "APPROVE"\n'

text = text[:start] + new_function + text[end:]
controller.write_text(text, encoding="utf-8")

print("Dashboard approval bridge applied successfully.")
print(controller)
