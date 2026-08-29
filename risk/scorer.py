import json
from pathlib import Path
PERMISSION_FILE = Path("reports/permission_analysis.json")
ORPHAN_FILE = Path("reports/orphan_report.json")
TEMPORAL_FILE = Path("reports/temporal_report.json")
IDENTITY_FILE = Path("reports/identity_report.json")
OUTPUT_FILE = Path("reports/risk_report.json")
def load_json(path):
    if not path.exists():
        print(f"WARNING: {path} not found.")
        return None
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON file: {path}")
        return None
def load_identity_classification():
    data = load_json(IDENTITY_FILE)
    identity_map = {}
    if not data:
        return identity_map
    for item in data.get("identities", []):
        identity = item.get("identity")
        if identity:
            identity_map[identity] = {
                "type": item.get(
                    "identity_type",
                    "Unknown"
                ),
                "confidence": item.get(
                    "confidence",
                    "Low"
                )
            }
    return identity_map
def get_permission_risk(user):
    analysis = user.get("analysis", {})
    broad_policies = analysis.get(
        "broad_policies",
        []
    )
    excessive_policies = analysis.get(
        "potentially_excessive_policies",
        []
    )
    score = 0
    if "AdministratorAccess" in broad_policies:
        score += 50
    for policy in excessive_policies:
        if policy.endswith("FullAccess"):
            score += 30
    if score > 100:
        score = 100
    return score
def get_usage_risk(user):
    api_calls = user.get(
        "observed_api_calls",
        0
    )
    services = user.get(
        "observed_services",
        []
    )
    score = 0
    if api_calls == 0:
        score = 0
    elif api_calls < 5:
        score = 20
    elif api_calls < 20:
        score = 30
    else:
        score = 40
    if len(services) > 5:
        score += 20
    if score > 100:
        score = 100
    return score
def get_orphan_risk(username, orphan_data):
    if not orphan_data:
        return 0
    if isinstance(orphan_data, list):
        records = orphan_data
    elif isinstance(orphan_data, dict):
        records = (
            orphan_data.get("users")
            or orphan_data.get("results")
            or []
        )
    else:
        records = []
    for item in records:
        if not isinstance(item, dict):
            continue
        item_user = (
            item.get("username")
            or item.get("user")
            or item.get("User")
        )
        if item_user != username:
            continue
        risk = item.get("risk")
        if isinstance(risk, str):
            risk = risk.lower()
            if risk == "high":
                return 30
            if risk == "medium":
                return 15
            return 0
        if isinstance(risk, (int, float)):
            return min(int(risk), 30)
    return 0
def get_temporal_risk(username, temporal_data):
    if not temporal_data:
        return 0
    if isinstance(temporal_data, list):
        records = temporal_data
    elif isinstance(temporal_data, dict):
        records = (
            temporal_data.get("users")
            or temporal_data.get("results")
            or temporal_data.get("identities")
            or []
        )
    else:
        records = []
    for item in records:
        if not isinstance(item, dict):
            continue
        item_user = (
            item.get("username")
            or item.get("user")
            or item.get("identity")
        )
        if item_user != username:
            continue
        risk = item.get("risk")
        if isinstance(risk, str):
            risk = risk.lower()
            if risk == "high":
                return 20
            if risk == "medium":
                return 10
            return 0
        if isinstance(risk, (int, float)):
            return min(int(risk), 20)
    return 0
def get_identity_adjustment(identity_type):
    if identity_type == "IAM User":
        return 0
    if identity_type == "IAM Role":
        return 0
    if identity_type == "AWS Service Identity":
        return 0
    if identity_type in ["Unknown", "Unresolved"]:
        return 5
    return 5
def get_risk_level(score):
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"
def main():
    print("=" * 60)
    print("          IDENTITY-AWARE RISK SCORING ENGINE")
    print("=" * 60)
    permission_data = load_json(PERMISSION_FILE)
    orphan_data = load_json(ORPHAN_FILE)
    temporal_data = load_json(TEMPORAL_FILE)
    identity_map = load_identity_classification()
    if not permission_data:
        print("ERROR: Permission analysis data unavailable.")
        return
    users = permission_data.get(
        "users",
        []
    )
    results = []
    for user in users:
        username = user.get(
            "username",
            "Unknown"
        )
        identity_info = identity_map.get(
            username,
            {
                "type": "Unknown",
                "confidence": "Low"
            }
        )
        identity_type = identity_info["type"]
        confidence = identity_info["confidence"]
        permission_risk = get_permission_risk(user)
        usage_risk = get_usage_risk(user)
        orphan_risk = get_orphan_risk(
            username,
            orphan_data
        )
        temporal_risk = get_temporal_risk(
            username,
            temporal_data
        )
        identity_adjustment = get_identity_adjustment(
            identity_type
        )
        total_risk = (
            permission_risk
            + usage_risk
            + orphan_risk
            + temporal_risk
            + identity_adjustment
        )
        if total_risk > 100:
            total_risk = 100
        risk_level = get_risk_level(
            total_risk
        )
        result = {
            "username": username,
            "identity_type": identity_type,
            "identity_confidence": confidence,
            "permission_risk": permission_risk,
            "usage_risk": usage_risk,
            "orphan_risk": orphan_risk,
            "temporal_risk": temporal_risk,
            "identity_adjustment":
                identity_adjustment,
            "total_risk":
                total_risk,
            "risk_level":
                risk_level
        }
        results.append(result)
        print()
        print("User:", username)
        print(
            "Identity Type:",
            identity_type
        )
        print(
            "Identity Confidence:",
            confidence
        )
        print(
            "Permission Risk:",
            permission_risk
        )
        print(
            "Usage Risk:",
            usage_risk
        )
        print(
            "Orphan Risk:",
            orphan_risk
        )
        print(
            "Temporal Risk:",
            temporal_risk
        )
        print(
            "Identity Adjustment:",
            identity_adjustment
        )
        print(
            "Total Risk:",
            total_risk
        )
        print(
            "Risk Level:",
            risk_level
        )
    report = {
        "module":
            "Identity-Aware Risk Scoring",
        "description":
            "Calculates risk using permission, usage, "
            "orphan, temporal and identity classification data.",
        "users":
            results
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
    print("Identity-Aware Risk Scoring Completed")
    print(
        "Report saved to:",
        OUTPUT_FILE
    )
    print("=" * 60)
if __name__ == "__main__":
    main()