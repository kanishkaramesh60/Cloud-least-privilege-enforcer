import boto3
import json
import os

session = boto3.Session(profile_name="leastprivilege")
cloudtrail = session.client("cloudtrail", region_name="ap-south-1")

print("=" * 60)
print("AWS CLOUDTRAIL LOG COLLECTOR")
print("=" * 60)

response = cloudtrail.lookup_events(
    MaxResults=50
)

events = response["Events"]
data = []

print(f"\nTotal Events Found : {len(events)}\n")

for event in events:
    print("-" * 50)

    print("User        :", event.get("Username", "N/A"))
    print("Event       :", event["EventName"])
    print("Time        :", event["EventTime"])
    print("Source      :", event["EventSource"])

    # Extract detailed CloudTrail event
    aws_region = None

    if event.get("CloudTrailEvent"):
        try:
            detailed_event = json.loads(event["CloudTrailEvent"])
            aws_region = detailed_event.get("awsRegion")
        except json.JSONDecodeError:
            aws_region = None

    print("Region      :", aws_region if aws_region else "N/A")

    resources = []

    if event.get("Resources"):
        print("Resources   :")

        for resource in event["Resources"]:
            print(
                f"   {resource.get('ResourceType')} : "
                f"{resource.get('ResourceName')}"
            )

            resources.append({
                "resource_type": resource.get("ResourceType"),
                "resource_name": resource.get("ResourceName")
            })

    else:
        print("Resources   : None")

    data.append({
        "username": event.get("Username"),
        "event_name": event["EventName"],
        "event_time": str(event["EventTime"]),
        "event_source": event["EventSource"],
        "aws_region": aws_region,
        "resources": resources
    })


os.makedirs("reports", exist_ok=True)

with open("reports/cloudtrail_logs.json", "w") as file:
    json.dump(data, file, indent=4)

print("\n" + "=" * 60)
print("CloudTrail Log Collection Completed")
print("Report saved to reports/cloudtrail_logs.json")
print("=" * 60)