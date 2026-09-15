import json
import sys
import requests


API_URL = "http://127.0.0.1:5000/api/findings"


def severity_from_semgrep(result):
    metadata = result.get("extra", {}).get("metadata", {})

    severity = metadata.get("severity", "WARNING")

    severity = str(severity).upper()

    if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        return severity

    return "MEDIUM"


def main():

    if len(sys.argv) != 2:
        print("Usage: python scripts/ingest_semgrep.py <semgrep.json>")
        sys.exit(1)

    report_file = sys.argv[1]

    try:
        with open(report_file, "r", encoding="utf-8") as file:
            report = json.load(file)

    except FileNotFoundError:
        print(f"Report not found: {report_file}")
        sys.exit(1)

    except json.JSONDecodeError:
        print(f"Invalid JSON report: {report_file}")
        sys.exit(1)

    results = report.get("results", [])

    print(f"Semgrep findings discovered: {len(results)}")

    ingested = 0
    duplicates = 0
    failed = 0

    for result in results:

        check_id = result.get("check_id", "Unknown Semgrep rule")

        message = (
            result.get("extra", {})
            .get("message", "Semgrep security finding")
        )

        severity = severity_from_semgrep(result)

        path = result.get("path", "")

        start = result.get("start", {})
        line = start.get("line", "")

        payload = {
            "scanner": "Semgrep",
            "severity": severity,
            "vulnerability_type": "SAST",
            "title": message,
            "description": f"Semgrep rule: {check_id}",
            "file": path,
            "line": line,
            "cve": None,
            "cvss": None
        }

        try:

            response = requests.post(
                API_URL,
                json=payload,
                timeout=10
            )

            if response.status_code == 201:

                print(
                    f"[STORED] {severity} - {message}"
                )

                ingested += 1

            elif response.status_code == 200:

                print(
                    f"[DUPLICATE] {severity} - {message}"
                )

                duplicates += 1

            else:

                print(
                    f"[FAILED] HTTP {response.status_code}: "
                    f"{response.text}"
                )

                failed += 1

        except requests.RequestException as error:

            print(
                f"[FAILED] Could not connect to ResponseOne API: {error}"
            )

            failed += 1

    print()
    print("========================================")
    print("Semgrep ingestion complete")
    print("========================================")
    print(f"Stored findings : {ingested}")
    print(f"Duplicates      : {duplicates}")
    print(f"Failed          : {failed}")
    print("========================================")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
