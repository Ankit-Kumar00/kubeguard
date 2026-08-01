import yaml
import sys


def scan_yaml(file_path):

    with open(file_path, "r") as file:
        data = yaml.safe_load(file)

    issues = []

    pod_spec = (
        data.get("spec", {})
        .get("template", {})
        .get("spec", {})
    )

    container_specs = pod_spec.get("containers", [])

    for container in container_specs:

        security = container.get("securityContext", {})

        # Privileged Container
        if security.get("privileged") is True:
            issues.append("Critical: Privileged container enabled")

        # Run as Root
        if security.get("runAsUser") == 0:
            issues.append("High: Container running as root user")

        # Privilege Escalation
        if security.get("allowPrivilegeEscalation") is True:
            issues.append("High: Allow privilege escalation enabled")

        # Read Only Filesystem
        if security.get("readOnlyRootFilesystem") is False:
            issues.append("Medium: Read-only root filesystem disabled")

        # Image Latest Tag
        image = container.get("image", "")

        if ":latest" in image:
            issues.append("Medium: Image uses latest tag")

        # Resource Limits
        resources = container.get("resources", {})

        if "limits" not in resources:
            issues.append("Medium: Resource limits not defined")

        if "requests" not in resources:
            issues.append("Medium: Resource requests not defined")

    # Host Network
    if pod_spec.get("hostNetwork") is True:
        issues.append("High: Host network enabled")

    # Host PID
    if pod_spec.get("hostPID") is True:
        issues.append("Critical: Host PID enabled")

    # Host IPC
    if pod_spec.get("hostIPC") is True:
        issues.append("High: Host IPC enabled")

    # Seccomp
    if "seccompProfile" not in pod_spec:
        issues.append("Medium: seccompProfile not configured")

    # HostPath Volume
    volumes = pod_spec.get("volumes", [])

    for volume in volumes:
        if "hostPath" in volume:
            issues.append("High: HostPath volume mounted")

    if not issues:
        print("No security issues found")

    else:
        print("\nSecurity Issues Found:\n")

        for issue in issues:
            print("-", issue)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python scanner.py <yaml-file>")
        exit()

    scan_yaml(sys.argv[1])
