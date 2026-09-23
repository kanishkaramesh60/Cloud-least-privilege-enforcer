import json
from pathlib import Path
import fnmatch


POLICY_FILE = Path("reports/policies.json")
USAGE_FILE = Path("reports/usage_report.json")
CLOUDTRAIL_FILE = Path("reports/cloudtrail_logs.json")
OUTPUT_FILE = Path("reports/permission_analysis.json")


def load_json(path):

    if not path.exists():

        print(f"ERROR: {path} not found.")

        return None

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError:

        print(
            f"ERROR: Invalid JSON file: {path}"
        )

        return None


def get_policy_users(data):

    users = {}

    if not data:
        return users

    records = data.get(
        "users",
        []
    )

    for item in records:

        username = item.get(
            "username"
        )

        policies = item.get(
            "attached_policies",
            []
        )

        inline_policies = item.get(
            "inline_policies",
            []
        )

        all_policies = (
            policies +
            inline_policies
        )

        if username:

            users[username] = {
                "policy_names":
                    all_policies,

                "attached_policy_details":
                    item.get(
                        "attached_policy_details",
                        []
                    ),

                "inline_policy_details":
                    item.get(
                        "inline_policy_details",
                        []
                    )
            }

    return users


def get_usage_users(data):

    users = {}

    if not data:
        return users

    if not isinstance(
        data,
        list
    ):
        return users

    for item in data:

        username = item.get(
            "username"
        )

        if username:

            users[username] = item

    return users


def get_cloudtrail_actions(data):

    user_actions = {}

    if not data:
        return user_actions

    if not isinstance(
        data,
        list
    ):
        return user_actions

    for event in data:

        username = event.get(
            "username"
        )

        event_name = event.get(
            "event_name"
        )

        event_source = event.get(
            "event_source"
        )

        if not username:
            continue

        if not event_name or not event_source:
            continue

        service = event_source.split(
            "."
        )[0]

        action = (
            f"{service}:{event_name}"
        )

        if username not in user_actions:

            user_actions[username] = set()

        user_actions[
            username
        ].add(action)

    return user_actions


def normalize_actions(actions):

    if isinstance(
        actions,
        str
    ):

        return [actions]

    if isinstance(
        actions,
        list
    ):

        return actions

    return []


def extract_policy_actions(
    policy_details
):

    actions = []

    for policy in policy_details:

        document = policy.get(
            "document"
        )

        if not document:
            continue

        statements = document.get(
            "Statement",
            []
        )

        if isinstance(
            statements,
            dict
        ):

            statements = [
                statements
            ]

        for statement in statements:

            if statement.get(
                "Effect"
            ) != "Allow":

                continue

            statement_actions = normalize_actions(
                statement.get(
                    "Action",
                    []
                )
            )

            for action in statement_actions:

                if action not in actions:

                    actions.append(
                        action
                    )

    return sorted(actions)


def action_matches(
    observed_action,
    policy_action
):

    observed_action = (
        observed_action.lower()
    )

    policy_action = (
        policy_action.lower()
    )

    return fnmatch.fnmatchcase(
        observed_action,
        policy_action
    )


def find_matching_grants(
    observed_actions,
    granted_actions
):

    matched = {}

    for observed in observed_actions:

        matches = []

        for granted in granted_actions:

            if action_matches(
                observed,
                granted
            ):

                matches.append(
                    granted
                )

        matched[observed] = matches

    return matched


def analyze_user(
    username,
    policy_info,
    usage,
    cloudtrail_actions
):

    api_calls = usage.get(
        "total_api_calls",
        0
    )

    services = usage.get(
        "services_used",
        []
    )

    observed_actions = sorted(
        cloudtrail_actions
    )

    attached_policy_details = (
        policy_info.get(
            "attached_policy_details",
            []
        )
    )

    inline_policy_details = (
        policy_info.get(
            "inline_policy_details",
            []
        )
    )

    all_policy_details = (
        attached_policy_details +
        inline_policy_details
    )

    granted_actions = (
        extract_policy_actions(
            all_policy_details
        )
    )

    action_matches_report = (
        find_matching_grants(
            observed_actions,
            granted_actions
        )
    )

    covered_observed_actions = []

    uncovered_observed_actions = []

    for observed_action in observed_actions:

        matches = action_matches_report.get(
            observed_action,
            []
        )

        if matches:

            covered_observed_actions.append(
                observed_action
            )

        else:

            uncovered_observed_actions.append(
                observed_action
            )

    potentially_unused_actions = []

    for granted_action in granted_actions:

        used = False

        for observed_action in observed_actions:

            if action_matches(
                observed_action,
                granted_action
            ):

                used = True

                break

        if not used:

            potentially_unused_actions.append(
                granted_action
            )

    broad_policies = []

    potentially_excessive_policies = []

    policy_usage = []

    for policy in all_policy_details:

        policy_name = policy.get(
            "policy_name"
        )

        policy_document = policy.get(
            "document"
        )

        policy_actions = []

        if policy_document:

            policy_actions = extract_policy_actions(
                [policy]
            )

        policy_observed_matches = []

        for observed_action in observed_actions:

            for policy_action in policy_actions:

                if action_matches(
                    observed_action,
                    policy_action
                ):

                    policy_observed_matches.append(
                        observed_action
                    )

                    break

        policy_observed_matches = sorted(
            set(policy_observed_matches)
        )

        policy_unused_actions = []

        for policy_action in policy_actions:

            used = False

            for observed_action in policy_observed_matches:

                if action_matches(
                    observed_action,
                    policy_action
                ):

                    used = True

                    break

            if not used:

                policy_unused_actions.append(
                    policy_action
                )

        if (
            policy_name == "AdministratorAccess"
        ):

            broad_policies.append(
                policy_name
            )

            potentially_excessive_policies.append(
                policy_name
            )

        elif policy_name.endswith(
            "FullAccess"
        ):

            broad_policies.append(
                policy_name
            )

            potentially_excessive_policies.append(
                policy_name
            )

        elif (
            policy_actions
            and not policy_observed_matches
        ):

            potentially_excessive_policies.append(
                policy_name
            )

        policy_usage.append({

            "policy_name":
                policy_name,

            "policy_type":
                policy.get(
                    "policy_type",
                    "Unknown"
                ),

            "granted_actions":
                policy_actions,

            "observed_actions":
                policy_observed_matches,

            "potentially_unused_actions":
                policy_unused_actions

        })

    potentially_excessive_policies = sorted(
        set(
            potentially_excessive_policies
        )
    )

    if not policy_info.get(
        "policy_names"
    ):

        status = "No Policies"

    elif not services:

        status = "No Observed Usage"

    elif potentially_excessive_policies:

        status = "Potentially Over-Privileged"

    elif uncovered_observed_actions:

        status = "Requires Policy Review"

    elif potentially_unused_actions:

        status = "Potentially Unused Permissions"

    else:

        status = "Least Privilege Consistent With Observed Usage"

    analysis = {

        "username":
            username,

        "assigned_policies":
            policy_info.get(
                "policy_names",
                []
            ),

        "observed_api_calls":
            api_calls,

        "observed_services":
            services,

        "observed_iam_actions":
            observed_actions,

        "granted_actions":
            granted_actions,

        "covered_observed_actions":
            covered_observed_actions,

        "uncovered_observed_actions":
            uncovered_observed_actions,

        "potentially_unused_actions":
            potentially_unused_actions,

        "policy_usage":
            policy_usage,

        "analysis": {

            "broad_policies":
                broad_policies,

            "potentially_excessive_policies":
                potentially_excessive_policies,

            "used_services":
                services,

            "unused_services":
                [],

            "least_privilege_status":
                status
        }
    }

    return analysis


def main():

    print("=" * 60)

    print(
        "        LEAST-PRIVILEGE PERMISSION ANALYZER"
    )

    print("=" * 60)

    policy_data = load_json(
        POLICY_FILE
    )

    usage_data = load_json(
        USAGE_FILE
    )

    cloudtrail_data = load_json(
        CLOUDTRAIL_FILE
    )

    if policy_data is None:
        return

    if usage_data is None:
        return

    if cloudtrail_data is None:
        return

    policy_users = get_policy_users(
        policy_data
    )

    usage_users = get_usage_users(
        usage_data
    )

    cloudtrail_actions = (
        get_cloudtrail_actions(
            cloudtrail_data
        )
    )

    all_users = set()

    all_users.update(
        policy_users.keys()
    )

    all_users.update(
        usage_users.keys()
    )

    all_users.update(
        cloudtrail_actions.keys()
    )

    results = []

    for username in sorted(
        all_users
    ):

        policy_info = policy_users.get(
            username,
            {
                "policy_names": [],
                "attached_policy_details": [],
                "inline_policy_details": []
            }
        )

        usage = usage_users.get(
            username,
            {}
        )

        actions = cloudtrail_actions.get(
            username,
            set()
        )

        result = analyze_user(
            username,
            policy_info,
            usage,
            actions
        )

        results.append(
            result
        )

        print()

        print(
            "User:",
            username
        )

        print(
            "Assigned Policies:",
            result["assigned_policies"]
        )

        print(
            "API Calls:",
            result["observed_api_calls"]
        )

        print(
            "Services Used:",
            result["observed_services"]
        )

        print(
            "Observed Actions:",
            result["observed_iam_actions"]
        )

        print(
            "Granted Actions:",
            result["granted_actions"]
        )

        print(
            "Potentially Unused Actions:",
            result["potentially_unused_actions"]
        )

        print(
            "Uncovered Observed Actions:",
            result["uncovered_observed_actions"]
        )

        print(
            "Broad Policies:",
            result["analysis"]["broad_policies"]
        )

        print(
            "Potentially Excessive Policies:",
            result["analysis"][
                "potentially_excessive_policies"
            ]
        )

        print(
            "Status:",
            result["analysis"][
                "least_privilege_status"
            ]
        )

    report = {

        "module":
            "Least-Privilege Permission Analysis",

        "description":
            "Compares assigned IAM policy permissions with observed CloudTrail usage.",

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

    print(
        "Least-Privilege Analysis Completed"
    )

    print(
        "Report saved to:",
        OUTPUT_FILE
    )

    print("=" * 60)


if __name__ == "__main__":

    main()