import json
from pathlib import Path

INPUT_FILE = Path("reports/cloudtrail_logs.json")
OUTPUT_FILE = Path("reports/observed_actions.json")

def load_json(path):
    if not path.exists():
        print(f"ERROR: {path} not found.")
        return None

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON: {path}")
        return None

def get_action(event):
    event_source = event.get("event_source")
    event_name = event.get("event_name")

    if not event_source or not event_name:
        return None

    service = event_source.split(".")[0]

    return f"{service}:{event_name}"

def main():

    print("=" * 60)
    print("       CLOUDTRAIL IAM ACTION EXTRACTION")
    print("=" * 60)

    data = load_json(INPUT_FILE)

    if data is None:
        return

    if not isinstance(data, list):
        print("ERROR: Expected CloudTrail data to be a list.")
        return

    print("CloudTrail records:", len(data))

    observed = {}

    for event in data:

        if not isinstance(event, dict):
            continue

        username = event.get("username")

        if not username:
            username = "Unknown"

        action = get_action(event)

        if not action:
            continue

        if username not in observed:
            observed[username] = []

        if action not in observed[username]:
            observed[username].append(action)

    results = []

    for username in sorted(observed):

        actions = sorted(observed[username])

        result = {
            "username": username,
            "observed_actions": actions,
            "action_count": len(actions)
        }

        results.append(result)

        print()
        print("Identity:", username)
        print("Observed Actions:")

        for action in actions:
            print("   ", action)

        print("Action Count:", len(actions))

    report = {
        "module": "CloudTrail IAM Action Extraction",
        "description": "Extracts IAM-style actions from CloudTrail event_source and event_name.",
        "users": results
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print()
    print("=" * 60)
    print("IAM ACTION EXTRACTION COMPLETED")
    print("Report saved to:", OUTPUT_FILE)
    print("=" * 60)

if __name__ == "__main__":
    main()