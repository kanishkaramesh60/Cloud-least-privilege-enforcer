import subprocess
import sys
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent


PIPELINE = [

    (
        "IAM Scanner",
        "scanner\\iam_scanner.py"
    ),

    (
        "CloudTrail Collector",
        "cloudtrail\\collector.py"
    ),

    (
        "CloudTrail Analyzer",
        "cloudtrail\\analyzer.py"
    ),

    (
        "Action Mapper",
        "action_mapper\\mapper.py"
    ),

    (
        "Identity Classification",
        "identity\\classifier.py"
    ),

    (
        "Orphan Detection",
        "orphan\\detector.py"
    ),

    (
        "Temporal Analysis",
        "temporal\\analyzer.py"
    ),

    (
        "Permission Analysis",
        "least_privilege\\analyzer.py"
    ),

    (
        "Risk Scoring",
        "risk\\scorer.py"
    ),

    (
        "XGBoost Risk Prediction",
        "ml\\predict_risk.py"
    ),

    (
        "AI Policy Recommendation",
        "ai\\policy_recommender.py"
    ),

    (
        "Policy Validation",
        "validation\\policy_validator.py"
    ),

    (
        "IAM Policy Simulation",
        "validation\\policy_simulator.py"
    ),

    (
        "Verification Controller",
        "validation\\verification_controller.py"
    ),
    (
        "Rollback Controller",
        "validation\\rollback_controller.py"
    ),
    (
        "Rollback Verification",
        "validation\\rollback_verification.py"
    ),
    (
        "Deployment Review",
        "validation\\deployment_review.py"
    ),
    (
        "Deployment Controller",
        "validation\\deployment_controller.py"
    ),
    (
        "Post-Deployment Verification",
        "validation\\post_deployment_verification.py"
    )
]


def run_module(name, script):

    print()
    print("=" * 70)
    print(name)
    print("=" * 70)

    script_path = BASE_DIR / script

    if not script_path.exists():

        print()
        print("ERROR: Module not found:")
        print(script_path)

        return False

    print()
    print("Running:")
    print(script_path)

    result = subprocess.run(
        [
            sys.executable,
            str(script_path)
        ],
        cwd=BASE_DIR
    )

    if result.returncode != 0:

        print()
        print("=" * 70)
        print(name, ": FAILED")
        print("=" * 70)

        return False

    print()
    print("=" * 70)
    print(name, ": COMPLETED")
    print("=" * 70)

    return True


def main():

    start_time = datetime.now()

    print("=" * 70)
    print("        CLOUD LEAST PRIVILEGE ENFORCER")
    print("             END-TO-END PIPELINE")
    print("=" * 70)

    print()
    print("Project Directory:")
    print(BASE_DIR)

    print()
    print("Pipeline Start Time:")
    print(start_time)

    completed = []
    failed = []

    for name, script in PIPELINE:

        success = run_module(
            name,
            script
        )

        if success:

            completed.append(name)

        else:

            failed.append(name)

            print()
            print("=" * 70)
            print("PIPELINE STOPPED")
            print("=" * 70)

            print()
            print("Failed Module:")
            print(name)

            break

    end_time = datetime.now()

    print()
    print("=" * 70)
    print("             PIPELINE SUMMARY")
    print("=" * 70)

    print()
    print("Completed Modules:")
    print("-" * 70)

    for module in completed:

        print(
            "[PASS]",
            module
        )

    if failed:

        print()
        print("Failed Module:")
        print("-" * 70)

        for module in failed:

            print(
                "[FAIL]",
                module
            )

    print()
    print("Start Time:")
    print(start_time)

    print()
    print("End Time:")
    print(end_time)

    print()
    print("=" * 70)

    if failed:

        print(
            "FINAL PIPELINE STATUS: FAILED"
        )

    else:

        print(
            "FINAL PIPELINE STATUS: COMPLETED"
        )

    print("=" * 70)


if __name__ == "__main__":

    main()