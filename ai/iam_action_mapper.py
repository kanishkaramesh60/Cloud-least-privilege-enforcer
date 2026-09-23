# ============================================================
# CLOUDTRAIL API ACTION -> IAM POLICY ACTION MAPPING
# ============================================================

IAM_ACTION_MAP = {
    "s3:ListBuckets": "s3:ListAllMyBuckets",
}


def map_cloudtrail_action(action):
    """
    Convert a CloudTrail API operation into its IAM
    policy action equivalent.

    Returns None when there is no confirmed mapping.
    """

    return IAM_ACTION_MAP.get(action)


def map_actions(actions):
    """
    Map CloudTrail actions to IAM policy actions.

    Only confirmed mappings are returned.
    Unmapped actions are excluded because they
    should not automatically become permissions.
    """

    mapped_actions = []

    for action in actions:

        mapped_action = map_cloudtrail_action(action)

        if mapped_action and mapped_action not in mapped_actions:
            mapped_actions.append(mapped_action)

    return mapped_actions


def get_unmapped_actions(actions):
    """
    Return CloudTrail actions for which we do not
    have a confirmed IAM mapping.
    """

    unmapped_actions = []

    for action in actions:

        if action not in IAM_ACTION_MAP:
            unmapped_actions.append(action)

    return unmapped_actions


if __name__ == "__main__":

    test_actions = [
        "s3:ListBuckets",
        "sts:GetCallerIdentity"
    ]

    print("CloudTrail Actions:")
    for action in test_actions:
        print(" -", action)

    print()

    print("Mapped IAM Policy Actions:")
    for action in map_actions(test_actions):
        print(" -", action)

    print()

    print("Unmapped / Context Actions:")
    for action in get_unmapped_actions(test_actions):
        print(" -", action)