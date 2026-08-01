import yaml
import sys


def scan_yaml(file_path):

    with open(file_path, "r") as file:
        data = yaml.safe_load(file)

    issues = []

    container_specs = (
        data.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )

    for container in container_specs:

        security = container.get("securityContext", {})

        if security.get("privileged") is True:
            issues.append(
                "Critical: Privileged container enabled"
            )

        if security.get("runAsUser") == 0:
            issues.append(
                "High: Container running as root user"
            )

    pod_spec = (
        data.get("spec", {})
        .get("template", {})
        .get("spec", {})
    )

    if pod_spec.get("hostNetwork") is True:
        issues.append(
            "High: Host network enabled"
        )


    if not issues:
        print(" No security issues found")

    else:
        print("\n Security Issues Found:\n")

        for issue in issues:
            print("-", issue)



if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(
            "Usage: python scanner.py <yaml-file>"
        )
        exit()

    scan_yaml(sys.argv[1])