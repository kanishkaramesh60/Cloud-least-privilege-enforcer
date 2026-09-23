import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime


INPUT_FILE = Path("reports/cloudtrail_logs.json")
OUTPUT_FILE = Path("reports/cloudtrail_analysis.json")

ACCESS_START_HOUR = 9
ACCESS_END_HOUR = 18


# Actions that should be treated as sensitive/high-impact
SENSITIVE_ACTIONS = {
    "CreateUser",
    "DeleteUser",
    "CreateAccessKey",
    "DeleteAccessKey",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "DetachUserPolicy",
    "DetachRolePolicy",
    "DetachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "CreatePolicy",
    "CreatePolicyVersion",
    "DeletePolicy",
    "DeletePolicyVersion",
    "UpdateAssumeRolePolicy",
    "PassRole",
    "AssumeRole",
    "CreateRole",
    "DeleteRole",
}


def load_logs():
    if not INPUT_FILE.exists():
        print(f"ERROR: {INPUT_FILE} not found.")
        return []

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, list):
            print("ERROR: CloudTrail log file must contain a list.")
            return []

        return data

    except json.JSONDecodeError:
        print("ERROR: Invalid JSON in cloudtrail_logs.json")
        return []


def get_service(event_source):
    if not event_source:
        return "Unknown"

    return event_source.replace(".amazonaws.com", "").upper()


def get_iam_action(event_source, event_name):
    if not event_source or not event_name:
        return None

    service = event_source.replace(".amazonaws.com", "")

    # CloudTrail event names are API operations.
    return f"{service}:{event_name}"


def is_sensitive_action(event_name):
    return event_name in SENSITIVE_ACTIONS


def analyze_logs(logs):
    users = defaultdict(
        lambda: {
            "total_api_calls": 0,
            "services": set(),
            "actions": set(),
            "sensitive_actions": set(),
            "outside_access_window": 0,
            "inside_access_window": 0,
            "resources": [],
            "regions": set(),
            "event_details": []
        }
    )

    for event in logs:
        if not isinstance(event, dict):
            continue

        username = event.get("username") or "Unknown"

        event_name = event.get("event_name")
        event_source = event.get("event_source")
        event_time = event.get("event_time")
        aws_region = event.get("aws_region")

        user = users[username]

        user["total_api_calls"] += 1

        service = get_service(event_source)

        if service != "Unknown":
            user["services"].add(service)

        iam_action = get_iam_action(event_source, event_name)

        if iam_action:
            user["actions"].add(iam_action)

        if is_sensitive_action(event_name):
            user["sensitive_actions"].add(iam_action)

        if aws_region:
            user["regions"].add(aws_region)

        # Analyze access time
        inside_access_window = None

        if event_time:
            try:
                timestamp = datetime.fromisoformat(event_time)

                if (
                    ACCESS_START_HOUR
                    <= timestamp.hour
                    < ACCESS_END_HOUR
                ):
                    user["inside_access_window"] += 1
                    inside_access_window = True
                else:
                    user["outside_access_window"] += 1
                    inside_access_window = False

            except ValueError:
                pass

        # Preserve resource information
        resources = event.get("resources", [])

        if isinstance(resources, list):
            for resource in resources:
                if isinstance(resource, dict):
                    user["resources"].append(resource)

        user["event_details"].append(
            {
                "event_name": event_name,
                "event_source": event_source,
                "event_time": event_time,
                "aws_region": aws_region,
                "iam_action": iam_action,
                "inside_access_window": inside_access_window,
                "sensitive": is_sensitive_action(event_name)
            }
        )

    results = []

    for username, data in users.items():

        services = sorted(data["services"])
        actions = sorted(data["actions"])
        sensitive_actions = sorted(
            action for action in data["sensitive_actions"]
            if action
        )

        cross_service_access = len(services) > 1

        results.append(
            {
                "username": username,
                "total_api_calls": data["total_api_calls"],
                "services_used": services,
                "service_count": len(services),
                "observed_actions": actions,
                "sensitive_actions": sensitive_actions,
                "sensitive_action_count": len(sensitive_actions),
                "inside_access_window": data["inside_access_window"],
                "outside_access_window": data["outside_access_window"],
                "unusual_hour_access": data["outside_access_window"] > 0,
                "cross_service_access": cross_service_access,
                "regions": sorted(data["regions"]),
                "resource_count": len(data["resources"]),
                "resources": data["resources"],
                "event_details": data["event_details"]
            }
        )

    return results


def main():
    print("=" * 60)
    print("          CLOUDTRAIL BEHAVIOR ANALYSIS")
    print("=" * 60)

    logs = load_logs()

    if not logs:
        return

    print("CloudTrail events loaded:", len(logs))

    results = analyze_logs(logs)

    report = {
        "module": "CloudTrail Behavior Analysis",
        "description": (
            "Analyzes collected CloudTrail events for identity behavior, "
            "services, actions, sensitive operations, temporal activity "
            "and cross-service access."
        ),
        "configuration": {
            "access_start_hour": ACCESS_START_HOUR,
            "access_end_hour": ACCESS_END_HOUR
        },
        "limitations": [
            "Source IP is not available in the current collected log format.",
            "API success or failure status is not available.",
            "Inactive days cannot be calculated from this limited collection window.",
            "The current dataset represents the collected CloudTrail window, not necessarily seven days."
        ],
        "total_events": len(logs),
        "identities": results
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print()

    for identity in results:
        print("Identity:", identity["username"])
        print("API Calls:", identity["total_api_calls"])
        print("Services:", identity["services_used"])
        print("Sensitive Actions:", identity["sensitive_actions"])
        print("Outside Access Window:", identity["outside_access_window"])
        print("Cross-Service Access:", identity["cross_service_access"])
        print()

    print("=" * 60)
    print("CLOUDTRAIL ANALYSIS COMPLETED")
    print("Report saved to:", OUTPUT_FILE)
    print("=" * 60)


if __name__ == "__main__":
    main()