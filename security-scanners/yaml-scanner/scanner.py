import sys
import yaml
import json

def get_pod_specs(doc):
    """
    Given a Kubernetes manifest document, yield tuple of (resource_identifier, pod_spec)
    """
    if not isinstance(doc, dict):
        return
    
    kind = doc.get("kind")
    metadata = doc.get("metadata", {})
    name = metadata.get("name", "unnamed")
    resource_id = f"{kind}/{name}" if kind else f"Unknown/{name}"
    
    if not kind:
        return

    # Pod
    if kind == "Pod":
        spec = doc.get("spec")
        if isinstance(spec, dict):
            yield resource_id, spec

    # Standard Workloads with template
    elif kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"]:
        template = doc.get("spec", {}).get("template", {})
        spec = template.get("spec")
        if isinstance(spec, dict):
            yield resource_id, spec

    # CronJob
    elif kind == "CronJob":
        job_template = doc.get("spec", {}).get("jobTemplate", {})
        template = job_template.get("spec", {}).get("template", {})
        spec = template.get("spec")
        if isinstance(spec, dict):
            yield resource_id, spec

def scan_yaml(file_path):
    findings = []
    
    try:
        with open(file_path, "r") as file:
            # support multi-document yaml files
            docs = list(yaml.safe_load_all(file))
    except Exception as e:
        return [{
            "id": "KG-ERR",
            "resource": "File",
            "severity": "critical",
            "category": "Parsing",
            "message": f"Failed to parse YAML file: {str(e)}",
            "remediation": "Verify the YAML file has valid syntax."
        }]

    for doc in docs:
        if not doc:
            continue
            
        for resource_id, pod_spec in get_pod_specs(doc):
            # Pod-level checks
            
            # Host Network
            if pod_spec.get("hostNetwork") is True:
                findings.append({
                    "id": "KG-001",
                    "resource": resource_id,
                    "severity": "high",
                    "category": "Networking",
                    "message": f"Host network enabled for resource {resource_id}.",
                    "remediation": "Disable hostNetwork in the pod spec to isolate network namespaces."
                })
                
            # Host PID
            if pod_spec.get("hostPID") is True:
                findings.append({
                    "id": "KG-002",
                    "resource": resource_id,
                    "severity": "critical",
                    "category": "Isolation",
                    "message": f"Host PID namespace shared for resource {resource_id}.",
                    "remediation": "Set hostPID to false. Sharing host PID namespace allows containers to view and interact with host processes."
                })
                
            # Host IPC
            if pod_spec.get("hostIPC") is True:
                findings.append({
                    "id": "KG-003",
                    "resource": resource_id,
                    "severity": "high",
                    "category": "Isolation",
                    "message": f"Host IPC namespace shared for resource {resource_id}.",
                    "remediation": "Set hostIPC to false to prevent container access to host shared memory."
                })
                
            # Seccomp Profile
            if "seccompProfile" not in pod_spec:
                findings.append({
                    "id": "KG-004",
                    "resource": resource_id,
                    "severity": "medium",
                    "category": "Hardening",
                    "message": f"Seccomp profile not configured for resource {resource_id}.",
                    "remediation": "Configure securityContext.seccompProfile (recommended: RuntimeDefault or Localhost)."
                })
                
            # HostPath Volume
            volumes = pod_spec.get("volumes", [])
            if isinstance(volumes, list):
                for vol in volumes:
                    if isinstance(vol, dict) and "hostPath" in vol:
                        findings.append({
                            "id": "KG-005",
                            "resource": resource_id,
                            "severity": "high",
                            "category": "Hardening",
                            "message": f"HostPath volume '{vol.get('name')}' mounted in resource {resource_id}.",
                            "remediation": "Avoid hostPath volume mounts. Use persistentVolumeClaim or local persistent volumes instead."
                        })
            
            # Container-level checks
            containers = pod_spec.get("containers", [])
            init_containers = pod_spec.get("initContainers", [])
            all_containers = []
            
            if isinstance(containers, list):
                for c in containers:
                    if isinstance(c, dict):
                        all_containers.append((c, "Container"))
            if isinstance(init_containers, list):
                for c in init_containers:
                    if isinstance(c, dict):
                        all_containers.append((c, "Init Container"))
                        
            for container, c_type in all_containers:
                c_name = container.get("name", "unknown")
                sec_context = container.get("securityContext", {}) or {}
                
                # Privileged Container
                if sec_context.get("privileged") is True:
                    findings.append({
                        "id": "KG-006",
                        "resource": resource_id,
                        "severity": "critical",
                        "category": "Access Control",
                        "message": f"{c_type} '{c_name}' is running as privileged.",
                        "remediation": "Disable privileged mode. Privileged containers have access to all host devices."
                    })
                    
                # Run as Root
                if sec_context.get("runAsUser") == 0:
                    findings.append({
                        "id": "KG-007",
                        "resource": resource_id,
                        "severity": "high",
                        "category": "Access Control",
                        "message": f"{c_type} '{c_name}' runs as root (user 0).",
                        "remediation": "Set runAsUser to a non-zero value or set runAsNonRoot to true in the securityContext."
                    })
                    
                # Privilege Escalation
                if sec_context.get("allowPrivilegeEscalation") is not False:
                    # Default is True in K8s, so if not explicitly set to False, it is allowed
                    findings.append({
                        "id": "KG-008",
                        "resource": resource_id,
                        "severity": "high",
                        "category": "Access Control",
                        "message": f"{c_type} '{c_name}' allows privilege escalation.",
                        "remediation": "Set securityContext.allowPrivilegeEscalation to false to prevent subprocesses from gaining more privileges than parent process."
                    })
                    
                # Read-Only Root Filesystem
                if sec_context.get("readOnlyRootFilesystem") is not True:
                    findings.append({
                        "id": "KG-009",
                        "resource": resource_id,
                        "severity": "medium",
                        "category": "Hardening",
                        "message": f"{c_type} '{c_name}' does not use a read-only root filesystem.",
                        "remediation": "Set securityContext.readOnlyRootFilesystem to true to prevent malicious modifications to the container filesystem."
                    })
                    
                # Image Latest Tag
                image = container.get("image", "")
                if image:
                    tag_issue = False
                    if ":" not in image:
                        tag_issue = True
                    elif ":latest" in image:
                        tag_issue = True
                    
                    if tag_issue:
                        findings.append({
                            "id": "KG-010",
                            "resource": resource_id,
                            "severity": "medium",
                            "category": "Hardening",
                            "message": f"{c_type} '{c_name}' uses an image with the 'latest' tag or no tag ({image}).",
                            "remediation": "Pin the image to a specific version tag or digest instead of using latest/no tag."
                        })
                        
                # Resource Limits & Requests
                resources = container.get("resources", {}) or {}
                if "limits" not in resources:
                    findings.append({
                        "id": "KG-011",
                        "resource": resource_id,
                        "severity": "medium",
                        "category": "Resources",
                        "message": f"{c_type} '{c_name}' resource limits not defined.",
                        "remediation": "Define resource CPU and Memory limits to prevent denial of service (noisy neighbor issue)."
                    })
                if "requests" not in resources:
                    findings.append({
                        "id": "KG-012",
                        "resource": resource_id,
                        "severity": "medium",
                        "category": "Resources",
                        "message": f"{c_type} '{c_name}' resource requests not defined.",
                        "remediation": "Define resource CPU and Memory requests to allow Kubernetes scheduler to allocate workloads appropriately."
                    })
                    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps([{
            "id": "KG-ERR",
            "resource": "CLI",
            "severity": "high",
            "category": "Usage",
            "message": "Usage: python scanner.py <yaml-file>",
            "remediation": "Provide the YAML file path as an argument."
        }]))
        sys.exit(1)
        
    results = scan_yaml(sys.argv[1])
    print(json.dumps(results, indent=2))
