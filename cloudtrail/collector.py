import boto3
import json
import os

PROFILE = "leastprivilege"
REGION = "ap-south-1"
TARGET_IDENTITY = "LeastPrivilegeDemoUser"

session = boto3.Session(profile_name=PROFILE)
cloudtrail = session.client("cloudtrail", region_name=REGION)

print("=" * 60)
print("AWS CLOUDTRAIL LOG COLLECTOR")
print("=" * 60)

events = []

try:
    response = cloudtrail.lookup_events(
        LookupAttributes=[
            {
                "AttributeKey": "Username",
                "AttributeValue": TARGET_IDENTITY
            }
        ],
        MaxResults=50
    )

    events = response.get("Events", [])

except Exception as e:
    print("\nERROR while collecting CloudTrail events:")
    print(e)
    exit(1)

print(f"\nTarget Identity : {TARGET_IDENTITY}")
print(f"Total Events Found : {len(events)}\n")

data = []

for event in events:

    print("-" * 50)

    username = event.get("Username", "N/A")
    event_name = event.get("EventName", "N/A")
    event_time = event.get("EventTime")
    event_source = event.get("EventSource", "N/A")

    print("User        :", username)
    print("Event       :", event_name)
    print("Time        :", event_time)
    print("Source      :", event_source)

    # --------------------------------------------------
    # Extract detailed CloudTrail event
    # --------------------------------------------------

    aws_region = None

    if event.get("CloudTrailEvent"):
        try:
            detailed_event = json.loads(
                event["CloudTrailEvent"]
            )

            aws_region = detailed_event.get("awsRegion")

        except json.JSONDecodeError:
            aws_region = None

    print(
        "Region      :",
        aws_region if aws_region else "N/A"
    )

    # --------------------------------------------------
    # Extract resources
    # --------------------------------------------------

    resources = []

    if event.get("Resources"):

        print("Resources   :")

        for resource in event["Resources"]:

            resource_type = resource.get(
                "ResourceType"
            )

            resource_name = resource.get(
                "ResourceName"
            )

            print(
                f"   {resource_type} : "
                f"{resource_name}"
            )

            resources.append({
                "resource_type": resource_type,
                "resource_name": resource_name
            })

    else:
        print("Resources   : None")

    # --------------------------------------------------
    # Store normalized event
    # --------------------------------------------------

    data.append({
        "username": username,
        "event_name": event_name,
        "event_time": str(event_time),
        "event_source": event_source,
        "aws_region": aws_region,
        "resources": resources
    })


# ------------------------------------------------------
# Save report
# ------------------------------------------------------

os.makedirs("reports", exist_ok=True)

OUTPUT_FILE = "reports/cloudtrail_logs.json"

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        data,
        file,
        indent=4
    )


print("\n" + "=" * 60)
print("CloudTrail Log Collection Completed")
print("Report saved to:", OUTPUT_FILE)
print("Identity collected:", TARGET_IDENTITY)
print("Events collected:", len(data))
print("=" * 60)