import json
from pathlib import Path
import ollama

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"

MODEL = "llama3.2:3b"

PERMISSION_FILE = REPORTS_DIR / "permission_analysis.json"
IDENTITY_FILE = REPORTS_DIR / "identity_report.json"
RISK_FILE = REPORTS_DIR / "risk_report.json"
ACTIONS_FILE = REPORTS_DIR / "observed_actions.json"

OUTPUT_FILE = REPORTS_DIR / "ai_policy_analysis.json"


def load_json(path):
    if not path.exists():
        print(f"ERROR: File not found: {path}")
        return {}

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def main():

    permission_data = load_json(PERMISSION_FILE)
    identity_data = load_json(IDENTITY_FILE)
    risk_data = load_json(RISK_FILE)
    actions_data = load_json(ACTIONS_FILE)

    prompt = f"""
You are a cloud security AI specializing in AWS IAM least privilege.

Analyze the following security information.

PERMISSION ANALYSIS:
{json.dumps(permission_data, indent=2)}

IDENTITY CLASSIFICATION:
{json.dumps(identity_data, indent=2)}

RISK ANALYSIS:
{json.dumps(risk_data, indent=2)}

OBSERVED CLOUDTRAIL ACTIONS:
{json.dumps(actions_data, indent=2)}

Your tasks:

1. Identify identities with excessive permissions.
2. Explain why their permissions may be excessive.
3. Compare assigned permissions with observed actions.
4. Identify permissions that appear unnecessary.
5. Recommend which permissions should be retained.
6. Explain the security improvement.

Do NOT modify AWS.
Do NOT attach or delete any IAM policies.

Return your analysis in clear structured text.
"""

    print("\nSending security data to Ollama...")
    print("=" * 60)

    response = ollama.chat(
        model=MODEL,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    analysis = response["message"]["content"]

    print("\nAI POLICY ANALYSIS")
    print("=" * 60)
    print(analysis)

    output = {
        "model": MODEL,
        "analysis": analysis
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(output, file, indent=4)

    print("\nAI analysis saved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()