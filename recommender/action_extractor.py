import json
from pathlib import Path
CLOUDTRAIL_FILE = Path("reports/cloudtrail_logs.json")
OUTPUT_FILE = Path("reports/observed_actions.json")
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
def get_events(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in [
            "events",
            "Events",
            "records",
            "Records",
            "cloudtrail_events"
        ]:
            if key in data and isinstance(data[key], list):
                return data[key]
    return []
def get_username(event):
    username = (
        event.get("username")
        or event.get("Username")
        or event.get("user")
        or event.get("User")
    )
    if username:
        return username
    identity = event.get("userIdentity", {})
    if isinstance(identity, dict):
        username = identity.get("userName")
        if username:
            return username
        arn = identity.get("arn", "")
        if ":assumed-role/" in arn:
            try:
                role_part = arn.split(":assumed-role/")[1]
                role_name = role_part.split("/")[0]
                return role_name
            except Exception:
                pass
    return None
def get_event_name(event):
    return (
        event.get("eventName")
        or event.get("EventName")
        or event.get("event_name")
    )
def get_event_source(event):
    return (
        event.get("eventSource")
        or event.get("EventSource")
        or event.get("event_source")
    )
def source_to_service(event_source):
    if not event_source:
        return None
    service = event_source.split(".")[0]
    return service
def main():
    print("=" * 60)
    print("          CLOUDTRAIL ACTION EXTRACTOR")
    print("=" * 60)
    data = load_json(CLOUDTRAIL_FILE)
    if data is None:
        return
    events = get_events(data)
    if not events:
        print("ERROR: No CloudTrail events found.")
        return
    user_actions = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        username = get_username(event)
        event_name = get_event_name(event)
        event_source = get_event_source(event)
        if not username:
            continue
        if not event_name:
            continue
        service = source_to_service(event_source)
        if not service:
            continue
        action = f"{service}:{event_name}"
        if username not in user_actions:
            user_actions[username] = set()
        user_actions[username].add(action)
    results = []
    for username in sorted(user_actions):
        actions = sorted(user_actions[username])
        result = {
            "username": username,
            "observed_actions": actions,
            "action_count": len(actions)
        }
        results.append(result)
        print()
        print("User:", username)
        print("Observed Actions:")
        for action in actions:
            print(" -", action)
    report = {
        "module": "CloudTrail IAM Action Extraction",
        "description": (
            "Converts CloudTrail eventName and eventSource "
            "values into IAM-style API actions."
        ),
        "users": results
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
    print("CloudTrail Action Extraction Completed")
    print("Report saved to:", OUTPUT_FILE)
    print("=" * 60)
if __name__ == "__main__":
    main()