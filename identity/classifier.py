import json
from pathlib import Path
POLICY_FILE = Path("reports/policies.json")
USAGE_FILE = Path("reports/usage_report.json")
OUTPUT_FILE = Path("reports/identity_report.json")
def load_json(path):
    if not path.exists():
        print(f"ERROR: {path} not found.")
        return None
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON file: {path}")
        return None
def get_iam_users(policy_data):
    users = set()
    for user in policy_data.get("users", []):
        if isinstance(user, dict):
            username = user.get("username")
            if username:
                users.add(username)
    return users
def get_iam_roles(policy_data):
    roles = set()
    for role in policy_data.get("roles", []):
        if isinstance(role, dict):
            role_name = role.get("name")
            if role_name:
                roles.add(role_name)
    return roles
def get_usage_identities(usage_data):
    identities = set()
    if not isinstance(usage_data, list):
        return identities
    for item in usage_data:
        if not isinstance(item, dict):
            continue
        username = item.get("username")
        if username is not None:
            identities.add(str(username))
    return identities
def classify_identity(identity, iam_users, iam_roles):
    if identity in iam_users:
        return {
            "identity": identity,
            "identity_type": "IAM User",
            "confidence": "High"
        }
    if identity in iam_roles:
        return {
            "identity": identity,
            "identity_type": "IAM Role",
            "confidence": "High"
        }
    service_keywords = [
        "resource-explorer",
        "awsservice",
        "service-role",
        "elasticfilesystem",
        "trustedadvisor",
        "backup"
    ]
    identity_lower = identity.lower()
    for keyword in service_keywords:
        if keyword in identity_lower:
            return {
                "identity": identity,
                "identity_type": "AWS Service Identity",
                "confidence": "Medium"
            }
    return {
        "identity": identity,
        "identity_type": "Unresolved",
        "confidence": "Low"
    }
def main():
    print("=" * 60)
    print("             IDENTITY CLASSIFICATION")
    print("=" * 60)
    policy_data = load_json(POLICY_FILE)
    usage_data = load_json(USAGE_FILE)
    if policy_data is None:
        return
    if usage_data is None:
        return
    iam_users = get_iam_users(policy_data)
    iam_roles = get_iam_roles(policy_data)
    usage_identities = get_usage_identities(usage_data)
    all_identities = set()
    all_identities.update(iam_users)
    all_identities.update(iam_roles)
    all_identities.update(usage_identities)
    results = []
    for identity in sorted(all_identities):
        result = classify_identity(
            identity,
            iam_users,
            iam_roles
        )
        results.append(result)
        print()
        print("Identity:", result["identity"])
        print("Type:", result["identity_type"])
        print("Confidence:", result["confidence"])
    has_unknown = any(
        isinstance(item, dict) and item.get("username") is None
        for item in usage_data
    )
    if has_unknown:
        unknown_result = {
            "identity": "Unknown",
            "identity_type": "Unknown",
            "confidence": "Low"
        }
        results.append(unknown_result)
        print()
        print("Identity: Unknown")
        print("Type: Unknown")
        print("Confidence: Low")
    report = {
        "module": "Identity Classification",
        "description":
            "Classifies IAM and CloudTrail identities as "
            "IAM users, IAM roles, AWS service identities, "
            "or unresolved identities.",
        "identities": results
    }
    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=4
        )
    print()
    print("=" * 60)
    print("Identity Classification Completed")
    print(
        "Report saved to:",
        OUTPUT_FILE
    )
    print("=" * 60)
if __name__ == "__main__":
    main()