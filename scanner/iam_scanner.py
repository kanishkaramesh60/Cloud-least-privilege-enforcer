import boto3
import json
import os

session = boto3.Session(
    profile_name="leastprivilege",
    region_name="ap-south-1"
)

sts = session.client("sts")

identity = sts.get_caller_identity()

print("======================================")
print("AWS ACCOUNT CONNECTED")
print("Account ID:", identity["Account"])
print("ARN:", identity["Arn"])
print("======================================")

iam = boto3.client("iam")
data = {
    "users": [],
    "roles": [],
    "groups": [],
    "managed_policies": []
}

print("========== IAM USERS ==========\n")
users = iam.list_users()["Users"]
for user in users:
    print(user["UserName"])
    attached = iam.list_attached_user_policies(
        UserName=user["UserName"]
    )["AttachedPolicies"]
    inline = iam.list_user_policies(
        UserName=user["UserName"]
    )["PolicyNames"]
    data["users"].append({
        "username": user["UserName"],
        "arn": user["Arn"],
        "created": str(user["CreateDate"]),
        "attached_policies": [
            policy["PolicyName"] for policy in attached
        ],
        "inline_policies": inline
    })

print("\n========== IAM ROLES ==========\n")
roles = iam.list_roles()["Roles"]
for role in roles:
    print(role["RoleName"])
    data["roles"].append({
        "name": role["RoleName"],
        "arn": role["Arn"],
        "created": str(role["CreateDate"])
    })

print("\n========== IAM GROUPS ==========\n")
groups = iam.list_groups()["Groups"]
for group in groups:
    print(group["GroupName"])

    data["groups"].append({
        "name": group["GroupName"],
        "arn": group["Arn"],
        "created": str(group["CreateDate"])
    })

print("\n========== MANAGED POLICIES ==========\n")
policies = iam.list_policies(Scope="Local")["Policies"]
for policy in policies:
    print(policy["PolicyName"])
    policy_details = iam.get_policy(
        PolicyArn=policy["Arn"]
    )
    version = policy_details["Policy"]["DefaultVersionId"]
    policy_document = iam.get_policy_version(
        PolicyArn=policy["Arn"],
        VersionId=version
    )
    data["managed_policies"].append({
        "policy_name": policy["PolicyName"],
        "arn": policy["Arn"],
        "document": policy_document["PolicyVersion"]["Document"]
    })

print("\n========== ATTACHED POLICIES ==========\n")
for user in users:
    print(f"\nUser : {user['UserName']}")
    attached = iam.list_attached_user_policies(
        UserName=user["UserName"]
    )["AttachedPolicies"]
    if not attached:
        print("No Attached Policies")
    else:
        for policy in attached:
            print(policy["PolicyName"])

print("\n========== INLINE POLICIES ==========\n")
for user in users:
    print(f"\nUser : {user['UserName']}")
    inline = iam.list_user_policies(
        UserName=user["UserName"]
    )["PolicyNames"]
    if not inline:
        print("No Inline Policies")
    else:
        for policy in inline:
            print(policy)
os.makedirs("reports", exist_ok=True)
with open("reports/policies.json", "w") as file:
    json.dump(data, file, indent=4)

print("\n======================================")
print("IAM Scan Completed Successfully")
print("Report saved to reports/policies.json")
print("======================================")