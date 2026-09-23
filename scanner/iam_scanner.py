import boto3
import json
import os
from urllib.parse import unquote


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

iam = session.client("iam")


data = {
    "users": [],
    "roles": [],
    "groups": [],
    "managed_policies": []
}


def get_policy_document(policy_arn, version_id):
    response = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id
    )

    document = response["PolicyVersion"]["Document"]

    if isinstance(document, str):
        document = json.loads(unquote(document))

    return document


print("========== IAM USERS ==========\n")

users = iam.list_users()["Users"]

for user in users:

    username = user["UserName"]

    print(username)

    attached = iam.list_attached_user_policies(
        UserName=username
    )["AttachedPolicies"]

    inline = iam.list_user_policies(
        UserName=username
    )["PolicyNames"]

    attached_policy_details = []

    for policy in attached:

        policy_arn = policy["PolicyArn"]
        policy_name = policy["PolicyName"]

        try:

            policy_details = iam.get_policy(
                PolicyArn=policy_arn
            )

            default_version = policy_details[
                "Policy"
            ]["DefaultVersionId"]

            document = get_policy_document(
                policy_arn,
                default_version
            )

            attached_policy_details.append({
                "policy_name": policy_name,
                "policy_arn": policy_arn,
                "policy_type": (
                    "AWS Managed"
                    if policy_arn.startswith(
                        "arn:aws:iam::aws:policy/"
                    )
                    else "Customer Managed"
                ),
                "document": document
            })

        except Exception as error:

            print(
                f"WARNING: Could not retrieve "
                f"policy {policy_name}: {error}"
            )

            attached_policy_details.append({
                "policy_name": policy_name,
                "policy_arn": policy_arn,
                "policy_type": "Unknown",
                "document": None
            })

    inline_policy_details = []

    for policy_name in inline:

        try:

            response = iam.get_user_policy(
                UserName=username,
                PolicyName=policy_name
            )

            document = response["PolicyDocument"]

            if isinstance(document, str):
                document = json.loads(
                    unquote(document)
                )

            inline_policy_details.append({
                "policy_name": policy_name,
                "policy_type": "Inline",
                "document": document
            })

        except Exception as error:

            print(
                f"WARNING: Could not retrieve "
                f"inline policy {policy_name}: {error}"
            )

            inline_policy_details.append({
                "policy_name": policy_name,
                "policy_type": "Inline",
                "document": None
            })

    data["users"].append({

        "username": username,

        "arn": user["Arn"],

        "created": str(
            user["CreateDate"]
        ),

        "attached_policies": [
            policy["PolicyName"]
            for policy in attached
        ],

        "inline_policies": inline,

        "attached_policy_details":
            attached_policy_details,

        "inline_policy_details":
            inline_policy_details
    })


print("\n========== IAM ROLES ==========\n")

roles = iam.list_roles()["Roles"]

for role in roles:

    print(role["RoleName"])

    data["roles"].append({
        "name": role["RoleName"],
        "arn": role["Arn"],
        "created": str(
            role["CreateDate"]
        )
    })


print("\n========== IAM GROUPS ==========\n")

groups = iam.list_groups()["Groups"]

for group in groups:

    print(group["GroupName"])

    data["groups"].append({
        "name": group["GroupName"],
        "arn": group["Arn"],
        "created": str(
            group["CreateDate"]
        )
    })


print("\n========== MANAGED POLICIES ==========\n")

policies = iam.list_policies(
    Scope="Local"
)["Policies"]

for policy in policies:

    print(policy["PolicyName"])

    policy_details = iam.get_policy(
        PolicyArn=policy["Arn"]
    )

    version = policy_details[
        "Policy"
    ]["DefaultVersionId"]

    policy_document = get_policy_document(
        policy["Arn"],
        version
    )

    data["managed_policies"].append({

        "policy_name":
            policy["PolicyName"],

        "arn":
            policy["Arn"],

        "document":
            policy_document
    })


print("\n========== ATTACHED POLICIES ==========\n")

for user in users:

    print(
        f"\nUser : {user['UserName']}"
    )

    attached = iam.list_attached_user_policies(
        UserName=user["UserName"]
    )["AttachedPolicies"]

    if not attached:

        print("No Attached Policies")

    else:

        for policy in attached:

            print(
                policy["PolicyName"]
            )


print("\n========== INLINE POLICIES ==========\n")

for user in users:

    print(
        f"\nUser : {user['UserName']}"
    )

    inline = iam.list_user_policies(
        UserName=user["UserName"]
    )["PolicyNames"]

    if not inline:

        print("No Inline Policies")

    else:

        for policy in inline:

            print(policy)


os.makedirs(
    "reports",
    exist_ok=True
)

with open(
    "reports/policies.json",
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        data,
        file,
        indent=4
    )


print("\n======================================")
print("IAM Scan Completed Successfully")
print(
    "Report saved to reports/policies.json"
)
print("======================================")