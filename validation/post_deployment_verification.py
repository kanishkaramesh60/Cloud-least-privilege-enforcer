import json
import os

DEPLOYMENT_REPORT = "reports/deployment_controller_report.json"
AI_POLICY_REPORT = "reports/ai_recommended_policies.json"

OUTPUT_FILE = "reports/post_deployment_verification_report.json"

print("=" * 60)
print("POST-DEPLOYMENT VERIFICATION")
print("=" * 60)

# ============================================================
# LOAD REPORTS
# ============================================================

if not os.path.exists(DEPLOYMENT_REPORT):
    print("\nERROR: Deployment controller report not found.")
    raise SystemExit(1)

if not os.path.exists(AI_POLICY_REPORT):
    print("\nERROR: AI policy report not found.")
    raise SystemExit(1)

with open(DEPLOYMENT_REPORT, "r") as file:
    deployment_data = json.load(file)

with open(AI_POLICY_REPORT, "r") as file:
    ai_data = json.load(file)

identity_data = ai_data.get("identity", {})

if isinstance(identity_data, dict):
    identity = identity_data.get("name", "Unknown")
else:
    identity = identity_data

deployment_status = deployment_data.get(
    "deployment_status",
    deployment_data.get("status", "")
)

aws_changes = deployment_data.get(
    "aws_changes_performed",
    False
)

# ============================================================
# VERIFICATION
# ============================================================

print("\nIdentity:", identity)

print("\n1. DEPLOYMENT REPORT CHECK")
print("-" * 60)

if deployment_data:
    print("Status: PASS")
else:
    print("Status: FAIL")

# ============================================================

print("\n2. AWS CHANGE CHECK")
print("-" * 60)

print("AWS Changes Performed:", aws_changes)

if aws_changes is False:
    print("Status: PASS")
else:
    print("Status: REVIEW REQUIRED")

# ============================================================

print("\n3. DEPLOYMENT STATUS")
print("-" * 60)

print("Deployment Status:", deployment_status)

# ============================================================
# CURRENT SAFE DRY-RUN HANDLING
# ============================================================

if deployment_status == "NO_REMEDIATION_REQUIRED":

    verification_status = "NOT_REQUIRED"

    print("\nNo remediation was required.")
    print("No deployed IAM policy needs verification.")

elif aws_changes is False:

    verification_status = "DRY_RUN_VERIFIED"

    print("\nDRY RUN detected.")
    print("No AWS IAM state was modified.")
    print("Deployment verification completed safely.")

else:

    verification_status = "REVIEW_REQUIRED"

    print("\nAWS changes were reported.")
    print("Real post-deployment verification is not enabled yet.")

# ============================================================
# SAVE REPORT
# ============================================================

report = {
    "identity": identity,
    "deployment_status": deployment_status,
    "aws_changes_performed": aws_changes,
    "verification_status": verification_status
}

with open(OUTPUT_FILE, "w") as file:
    json.dump(report, file, indent=4)

print("\n" + "=" * 60)
print("POST-DEPLOYMENT VERIFICATION:", verification_status)
print("=" * 60)

print("\nReport saved:")
print(OUTPUT_FILE)