import json
import os
import boto3
from datetime import datetime
from urllib.parse import unquote

PROFILE = "leastprivilege"
REGION = "ap-south-1"
IDENTITY = "LeastPrivilegeDemoUser"

ROLLBACK_DIR = "reports/rollback"

os.makedirs(ROLLBACK_DIR, exist_ok=True)

print("=" * 60)
print("ROLLBACK CONTROLLER")
print("=" * 60)

session = boto3.Session(
    profile_name=PROFILE,
    region_name=REGION
)

iam = session.client("iam")

print("\nIdentity:", IDENTITY)
print("Identity Type: IAM User")

# ============================================================
# 1. MANAGED POLICIES
# ============================================================

print("\nCollecting managed policy state...")

attached_response = iam.list_attached_user_policies(
    UserName=IDENTITY
)

managed_policies = []

for policy in attached_response.get("AttachedPolicies", []):

    policy_arn = policy["PolicyArn"]
    policy_name = policy["PolicyName"]

    policy_info = iam.get_policy(
        PolicyArn=policy_arn
    )

    default_version = policy_info["Policy"]["DefaultVersionId"]

    version_response = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=default_version
    )

    document = version_response["PolicyVersion"]["Document"]

    managed_policies.append({
        "policy_name": policy_name,
        "policy_arn": policy_arn,
        "default_version_id": default_version,
        "policy_document": document
    })

print("\nAttached Managed Policies")

if managed_policies:
    for policy in managed_policies:
        print(" -", policy["policy_name"])
else:
    print(" - None")

# ============================================================
# 2. INLINE POLICIES
# ============================================================

print("\nCollecting inline policy state...")

inline_response = iam.list_user_policies(
    UserName=IDENTITY
)

inline_policies = []

for policy_name in inline_response.get("PolicyNames", []):

    response = iam.get_user_policy(
        UserName=IDENTITY,
        PolicyName=policy_name
    )

    document = response["PolicyDocument"]

    # AWS may return the policy document URL encoded
    if isinstance(document, str):
        document = json.loads(unquote(document))

    inline_policies.append({
        "policy_name": policy_name,
        "policy_document": document
    })

print("\nInline Policies")

if inline_policies:
    for policy in inline_policies:
        print(" -", policy["policy_name"])
else:
    print(" - None")

# ============================================================
# 3. CREATE COMPLETE SNAPSHOT
# ============================================================

snapshot = {
    "snapshot_time": datetime.now().isoformat(),
    "identity": IDENTITY,
    "identity_type": "IAM User",

    "attached_managed_policies": managed_policies,

    "inline_policies": inline_policies,

    "aws_changes_performed": False
}

snapshot_file = (
    f"{ROLLBACK_DIR}/{IDENTITY}_rollback_snapshot.json"
)

with open(snapshot_file, "w") as file:
    json.dump(snapshot, file, indent=4)

print("\n" + "=" * 60)
print("ROLLBACK SNAPSHOT CREATED")
print("=" * 60)

print("\nSnapshot:", snapshot_file)

print("\nManaged Policies Captured:",
      len(managed_policies))

print("Inline Policies Captured:",
      len(inline_policies))

print("\nAWS CHANGES PERFORMED : False")
print("ROLLBACK STATUS        : READY")