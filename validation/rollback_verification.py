import json
import os

SNAPSHOT_FILE = (
    "reports/rollback/LeastPrivilegeDemoUser_rollback_snapshot.json"
)

EXPECTED_IDENTITY = "LeastPrivilegeDemoUser"
EXPECTED_IDENTITY_TYPE = "IAM User"

print("=" * 60)
print("ROLLBACK SNAPSHOT VERIFICATION")
print("=" * 60)

if not os.path.exists(SNAPSHOT_FILE):
    print("\nStatus: FAIL")
    print("Rollback snapshot not found.")
    print("Expected:", SNAPSHOT_FILE)
    exit()

with open(SNAPSHOT_FILE, "r") as file:
    snapshot = json.load(file)

checks = []

# ============================================================
# 1. IDENTITY CHECK
# ============================================================

print("\n1. IDENTITY CHECK")
print("-" * 60)

if snapshot.get("identity") == EXPECTED_IDENTITY:
    print("Status: PASS")
    print("Identity:", EXPECTED_IDENTITY)
    checks.append(True)
else:
    print("Status: FAIL")
    print("Expected:", EXPECTED_IDENTITY)
    print("Found:", snapshot.get("identity"))
    checks.append(False)

# ============================================================
# 2. IDENTITY TYPE CHECK
# ============================================================

print("\n2. IDENTITY TYPE CHECK")
print("-" * 60)

if snapshot.get("identity_type") == EXPECTED_IDENTITY_TYPE:
    print("Status: PASS")
    print("Type:", EXPECTED_IDENTITY_TYPE)
    checks.append(True)
else:
    print("Status: FAIL")
    print("Expected:", EXPECTED_IDENTITY_TYPE)
    print("Found:", snapshot.get("identity_type"))
    checks.append(False)

# ============================================================
# 3. MANAGED POLICY SNAPSHOT
# ============================================================

managed = snapshot.get("attached_managed_policies", [])

print("\n3. MANAGED POLICY SNAPSHOT")
print("-" * 60)

if isinstance(managed, list):
    print("Status: PASS")

    if managed:
        for policy in managed:
            print(" -", policy["policy_name"])
            print("   ARN:", policy["policy_arn"])
    else:
        print(" - None")

    checks.append(True)

else:
    print("Status: FAIL")
    print("Managed policy data is not a list.")
    checks.append(False)

# ============================================================
# 4. INLINE POLICY SNAPSHOT
# ============================================================

inline = snapshot.get("inline_policies", [])

print("\n4. INLINE POLICY SNAPSHOT")
print("-" * 60)

if isinstance(inline, list):
    print("Status: PASS")

    if inline:
        for policy in inline:
            print(" -", policy["policy_name"])
    else:
        print(" - None")

    checks.append(True)

else:
    print("Status: FAIL")
    print("Inline policy data is not a list.")
    checks.append(False)

# ============================================================
# 5. AWS CHANGE CHECK
# ============================================================

aws_changes = snapshot.get("aws_changes_performed", True)

print("\n5. AWS CHANGE CHECK")
print("-" * 60)

if aws_changes is False:
    print("Status: PASS")
    print("No AWS changes were performed.")
    checks.append(True)

else:
    print("Status: FAIL")
    print("AWS changes were reported.")
    checks.append(False)

# ============================================================
# FINAL VERIFICATION
# ============================================================

print("\n" + "=" * 60)

if all(checks):
    print("ROLLBACK SNAPSHOT VERIFICATION: VERIFIED")
else:
    print("ROLLBACK SNAPSHOT VERIFICATION: FAILED")

print("=" * 60)