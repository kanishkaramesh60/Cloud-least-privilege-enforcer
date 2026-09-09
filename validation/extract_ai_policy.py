import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"
OUTPUT_FILE = BASE_DIR / "validation" / "ai_policy.json"


def main():

    if not INPUT_FILE.exists():
        print("ERROR: AI recommendation file not found.")
        print(INPUT_FILE)
        return

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        data = json.load(f)

    policy = data.get("recommended_policy")

    if not policy:
        print("ERROR: recommended_policy not found.")
        return

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            policy,
            f,
            indent=4
        )

    print("=" * 60)
    print("        AI POLICY EXTRACTED")
    print("=" * 60)

    print()
    print("Input:")
    print(INPUT_FILE)

    print()
    print("Output:")
    print(OUTPUT_FILE)

    print()
    print("IAM POLICY")
    print("-" * 60)

    print(
        json.dumps(
            policy,
            indent=4
        )
    )

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()