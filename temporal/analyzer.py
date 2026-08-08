import json
from datetime import datetime
from pathlib import Path

INPUT_FILE = Path("reports/cloudtrail_logs.json")
OUTPUT_FILE = Path("reports/temporal_report.json")

ACCESS_START_HOUR = 9
ACCESS_END_HOUR = 18

def load_cloudtrail_logs():
    if not INPUT_FILE.exists():
        print(f"ERROR: {INPUT_FILE} not found.")
        return []
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError:
        print("ERROR: cloudtrail_logs.json contains invalid JSON.")
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        possible_keys = [
            "events",
            "Events",
            "cloudtrail_events"
        ]
        for key in possible_keys:
            if key in data and isinstance(data[key], list):
                return data[key]
    print("ERROR: Could not find CloudTrail events.")
    return []

def get_identity(event):
    if event.get("Username"):
        return event["Username"]
    if event.get("username"):
        return event["username"]
    identity = event.get("userIdentity", {})
    if isinstance(identity, dict):
        username = identity.get("userName")
        if username:
            return username
        principal_id = identity.get("principalId")
        if principal_id:
            return principal_id
        identity_type = identity.get("type")
        if identity_type:
            return f"AWS:{identity_type}"
    return "Unknown"

def get_event_time(event):
    possible_fields = [
        "EventTime",
        "eventTime",
        "event_time"
    ]
    for field in possible_fields:
        if event.get(field):
            return event[field]
    return None

def get_event_name(event):
    possible_fields = [
        "EventName",
        "eventName",
        "event_name"
    ]
    for field in possible_fields:
        if event.get(field):
            return event[field]
    return "Unknown"

def get_event_source(event):
    possible_fields = [
        "EventSource",
        "eventSource",
        "event_source"
    ]
    for field in possible_fields:
        if event.get(field):
            return event[field]
    return "Unknown"

def parse_timestamp(timestamp):
    if not timestamp:
        return None
    try:
        timestamp = timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None

def analyze_event(event):
    identity = get_identity(event)
    event_time = get_event_time(event)
    event_name = get_event_name(event)
    event_source = get_event_source(event)
    timestamp = parse_timestamp(event_time)
    if timestamp is None:
        return {
            "username": identity,
            "event_name": event_name,
            "event_source": event_source,
            "event_time": event_time,
            "status": "Invalid Timestamp"
        }
    hour = timestamp.hour
    day = timestamp.strftime("%A")
    inside_access_window = (
        ACCESS_START_HOUR <= hour < ACCESS_END_HOUR
    )
    outside_access_window = not inside_access_window
    weekend = day in ["Saturday", "Sunday"]
    if outside_access_window:
        status = "Outside Access Window"
    else:
        status = "Within Access Window"
    return {
        "username": identity,
        "event_name": event_name,
        "event_source": event_source,
        "event_time": event_time,
        "hour": hour,
        "day": day,
        "inside_access_window": inside_access_window,
        "outside_access_window": outside_access_window,
        "weekend_activity": weekend,
        "status": status
    }

def main():
    print("=" * 50)
    print("       TEMPORAL ACCESS ANALYSIS")
    print("=" * 50)
    events = load_cloudtrail_logs()
    if not events:
        print("No CloudTrail events found.")
        return
    results = []
    for event in events:
        result = analyze_event(event)
        results.append(result)

    total_events = len(results)
    within_window = sum(
        1
        for result in results
        if result.get("status") == "Within Access Window"
    )
    outside_window = sum(
        1
        for result in results
        if result.get("status") == "Outside Access Window"
    )
    invalid_timestamp = sum(
        1
        for result in results
        if result.get("status") == "Invalid Timestamp"
    )
    weekend_events = sum(
        1
        for result in results
        if result.get("weekend_activity") is True
    )

    report = {
        "configuration": {
            "access_start_hour": ACCESS_START_HOUR,
            "access_end_hour": ACCESS_END_HOUR
        },
        "summary": {
            "total_events": total_events,
            "within_access_window": within_window,
            "outside_access_window": outside_window,
            "weekend_events": weekend_events,
            "invalid_timestamps": invalid_timestamp
        },
        "events": results
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
    print(f"\nTotal Events             : {total_events}")
    print(f"Within Access Window    : {within_window}")
    print(f"Outside Access Window   : {outside_window}")
    print(f"Weekend Events           : {weekend_events}")
    print(f"Invalid Timestamps       : {invalid_timestamp}")
    print("\n" + "=" * 50)
    print("Temporal Analysis Completed Successfully")
    print(f"Report saved to: {OUTPUT_FILE}")
    print("=" * 50)

if __name__ == "__main__":
    main()