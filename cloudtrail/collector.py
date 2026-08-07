import boto3
import json
import os

cloudtrail = boto3.client("cloudtrail")
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
    print("Region      :", event.get("AwsRegion", "N/A"))

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
        "aws_region": event.get("AwsRegion"),
        "resources": resources
    })

os.makedirs("reports", exist_ok=True)

with open("reports/cloudtrail_logs.json", "w") as file:
    json.dump(data, file, indent=4)

print("\n" + "=" * 60)
print("CloudTrail Log Collection Completed")
print("Report saved to reports/cloudtrail_logs.json")
print("=" * 60)