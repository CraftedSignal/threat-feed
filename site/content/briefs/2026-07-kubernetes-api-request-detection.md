---
title: Direct Kubernetes API Request Detected via Elastic Defend for Containers
slug: 2026-07-kubernetes-api-request-detection
description: Adversaries leveraging initial access within a container may execute direct Kubernetes API requests using tools like curl, wget, or kubectl, often with bearer tokens and insecure TLS, for cluster enumeration, lateral movement, or privilege escalation, which can be detected by Elastic Defend for Containers.
date: "2026-07-29T12:50:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - kubernetes
  - linux
  - threat-detection
  - execution
  - discovery
  - lateral-movement
vendors:
  - Kubernetes
products:
  - Kubernetes
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule flags use of curl, wget, openssl, busybox ssl_client, socat/ncat, or kubectl from inside a container, often from an interactive shell session.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: The rule detects direct Kubernetes API requests using tools like kubectl which is a container administration command.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: An operator enumerates cluster resources and tests access with in-pod credentials, enabling lateral movement or privilege escalation; after landing in a pod, they read the service account token and query the API to list namespaces, pods, or secrets.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The rule flags use of curl, wget, openssl, busybox ssl_client, socat/ncat, or kubectl from inside a container to call the Kubernetes API with a bearer token... An operator enumerates cluster resources and tests access with in-pod credentials, enabling lateral movement or privilege escalation.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/execution_direct_interactive_kubernetes_api_request.toml
rules:
  - title: Direct Kubernetes API Request Detected via Defend for Containers
    description: Detects suspicious direct Kubernetes API requests executed from within a container using tools like curl, wget, kubectl, openssl, socat, ncat, or busybox ssl_client, often with bearer tokens and insecure TLS options, indicating potential lateral movement or privilege escalation.
    platform: sigma
    severity: low
    tactics:
      - discovery
      - execution
      - lateral_movement
    techniques:
      - T1059
      - T1059.004
      - T1550
      - T1550.001
      - T1609
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat brief describes how adversaries, after gaining initial access to a containerized workload, may perform direct Kubernetes API requests to further their objectives within the cluster. This activity, detectable by Elastic Defend for Containers, involves executing commands such as `curl`, `wget`, `openssl`, `busybox ssl_client`, `socat`, `ncat`, or `kubectl` from within the compromised container. Attackers use these tools to interact with the Kubernetes API server, often supplying a bearer token for authentication and sometimes bypassing TLS verification with custom CA certificates or insecure options. The primary goal of such requests is typically to enumerate cluster resources like namespaces, pods, and secrets, facilitating lateral movement or privilege escalation to compromise the broader Kubernetes environment. This behavior is a critical post-exploitation indicator, signifying an adversary attempting to understand and expand their foothold beyond the initial container.

## Attack Chain

1. **Initial Access to Container**: An adversary gains unauthorized access to a container running within a Kubernetes cluster, typically through a vulnerable application, misconfiguration, or compromised credentials.
2. **Interactive Shell Execution**: The attacker establishes an interactive shell session (e.g., `bash`, `sh`) within the compromised container to execute commands.
3. **Service Account Token Discovery**: The attacker locates and extracts the Kubernetes service account bearer token, usually mounted within the container's filesystem at a well-known path (e.g., `/var/run/secrets/kubernetes.io/serviceaccount/token`).
4. **Kubernetes API Enumeration**: Using tools like `curl`, `wget`, or `kubectl`, the attacker crafts HTTP requests to the Kubernetes API server, authenticating with the discovered bearer token, to list and inspect cluster resources (e.g., `namespaces`, `pods`, `secrets`, `services`).
5. **Sensitive Data Exposure**: Successful enumeration reveals sensitive information, potentially including secret data from environment variables, mounted volumes, or Kubernetes `Secret` objects.
6. **Workload Modification or Creation**: The adversary attempts to modify existing cluster resources or create new ones (e.g., deploying new pods, updating configurations, patching deployments) to establish persistence or escalate privileges.
7. **Lateral Movement and Privilege Escalation**: Leveraging the access gained, the attacker moves laterally to other containers or nodes, or escalates privileges to achieve control over the entire Kubernetes cluster, potentially leading to full compromise.

## Impact

Successful exploitation allows adversaries to gain extensive access to the Kubernetes API server and associated cluster resources. This can lead to the enumeration and exfiltration of sensitive data, such as application secrets, configuration details, and user credentials. Attackers can leverage this access for lateral movement across the cluster, compromise additional workloads, and potentially achieve full control over the Kubernetes environment. The result may include resource manipulation, deployment of malicious containers, denial of service, or exfiltration of proprietary data, impacting data confidentiality, integrity, and system availability. No specific victim counts or financial damages are provided in the source, but the potential for severe operational disruption is high.

## Recommendation

* Deploy the Sigma rule "Direct Kubernetes API Request Detected via Defend for Containers" to your SIEM and tune for your environment to detect suspicious API interactions.
* Enable comprehensive process creation logging for Linux containers using Elastic Defend for Containers to activate this rule and ensure visibility into command execution.
* Implement strict NetworkPolicies within your Kubernetes cluster to restrict egress from containers to the Kubernetes API server (`default/kubernetes service`) unless explicitly required by the workload.
* Configure Kubernetes admission controls to enforce `automountServiceAccountToken: false` by default and ensure only short-lived, bound service account tokens are used where necessary.
* Harden container images by adopting distroless images that omit unnecessary tools like `curl`, `wget`, `openssl`, `ncat`, and `kubectl` to reduce the attack surface.
* Regularly review Kubernetes audit logs to identify and correlate `exec`/`attach`/`ephemeral-container` activity with detected API requests and user principals involved.
