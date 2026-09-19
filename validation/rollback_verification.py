import json
import os

SNAPSHOT_FILE = (
    "reports/rollback/Least_privilege_rollback_snapshot.json"
)

print("=" * 60)
print("ROLLBACK SNAPSHOT VERIFICATION")
print("=" * 60)

if not os.path.exists(SNAPSHOT_FILE):
    print("\nStatus: FAIL")
    print("Rollback snapshot not found.")
    exit()

with open(SNAPSHOT_FILE, "r") as file:
    snapshot = json.load(file)

checks = []

# 1. Identity
if snapshot.get("identity") == "Least_privilege":
    print("\n1. IDENTITY CHECK")
    print("-" * 60)
    print("Status: PASS")
    print("Identity: Least_privilege")
    checks.append(True)
else:
    print("\n1. IDENTITY CHECK")
    print("-" * 60)
    print("Status: FAIL")
    checks.append(False)

# 2. Identity type
if snapshot.get("identity_type") == "IAM User":
    print("\n2. IDENTITY TYPE CHECK")
    print("-" * 60)
    print("Status: PASS")
    print("Type: IAM User")
    checks.append(True)
else:
    print("\n2. IDENTITY TYPE CHECK")
    print("-" * 60)
    print("Status: FAIL")
    checks.append(False)

# 3. Managed policies
managed = snapshot.get("attached_managed_policies", [])

print("\n3. MANAGED POLICY SNAPSHOT")
print("-" * 60)
print("Status: PASS")

if managed:
    for policy in managed:
        print(" -", policy)
else:
    print(" - None")

checks.append(isinstance(managed, list))

# 4. Inline policies
inline = snapshot.get("inline_policies", [])

print("\n4. INLINE POLICY SNAPSHOT")
print("-" * 60)
print("Status: PASS")

if inline:
    for policy in inline:
        print(" -", policy)
else:
    print(" - None")

checks.append(isinstance(inline, list))

# 5. AWS change check
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

print("\n" + "=" * 60)

if all(checks):
    print("ROLLBACK SNAPSHOT VERIFICATION: VERIFIED")
else:
    print("ROLLBACK SNAPSHOT VERIFICATION: FAILED")

print("=" * 60)