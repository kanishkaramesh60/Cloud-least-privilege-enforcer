import subprocess
import json
import os

print("=" * 70)
print("       BEHAVIORAL & PERMISSION ANALYSIS")
print("=" * 70)

# Run Behavioral Analysis
print("\n[1] BEHAVIORAL ANALYSIS")
print("-" * 70)

result = subprocess.run(
    ["python", "cloudtrail_analysis.py"],
    capture_output=True,
    text=True
)

if result.returncode == 0:
    print("Behavioral analysis completed successfully.")
else:
    print("Behavioral analysis failed.")
    print(result.stderr)

# Run Permission Analysis
print("\n[2] PERMISSION ANALYSIS")
print("-" * 70)

result = subprocess.run(
    ["python", "least_privilege\\analyzer.py"],
    capture_output=True,
    text=True
)

if result.returncode == 0:
    print("Permission analysis completed successfully.")
else:
    print("Permission analysis failed.")
    print(result.stderr)

# Display Behavioral Analysis Report
print("\n" + "=" * 70)
print("BEHAVIORAL ANALYSIS RESULT")
print("=" * 70)

try:
    with open("reports/cloudtrail_analysis.json", "r") as file:
        behavioral = json.load(file)

    if isinstance(behavioral, dict):
        for key, value in behavioral.items():
            print(f"{key.replace('_', ' ').title():30}: {value}")

except Exception as e:
    print("Unable to read behavioral analysis report:", e)


# Display Permission Analysis Report
print("\n" + "=" * 70)
print("PERMISSION ANALYSIS RESULT")
print("=" * 70)

try:
    with open("reports/permission_analysis.json", "r") as file:
        permission = json.load(file)

    if isinstance(permission, dict):
        for key, value in permission.items():
            print(f"{key.replace('_', ' ').title():30}: {value}")

except Exception as e:
    print("Unable to read permission analysis report:", e)

print("\n" + "=" * 70)
print("ANALYSIS COMPLETED")
print("=" * 70)