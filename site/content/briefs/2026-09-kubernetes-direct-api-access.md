---
title: Detection of Unauthorized Kubernetes API Interaction via CLI Tools
slug: 2026-09-kubernetes-direct-api-access
description: Adversaries leverage standard command-line tools like curl or wget to perform unauthorized discovery and credential access by querying sensitive Kubernetes API endpoints directly, bypassing legitimate management tooling.
date: "2026-09-18T19:15:29Z"
lastmod: "2026-09-19T13:13:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Kubernetes
products:
  - Kubernetes API
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries may utilize standard command-line tools like curl or wget to perform direct, unauthorized queries.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: Adversaries attempt to stealthily discover cluster resources.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries attempt to stealthily discover sensitive configurations like secrets.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_kubernetes_direct_api_request_via_curl_or_wget.toml
rules:
  - title: Detect Unauthorized Kubernetes API Interaction via Curl or Wget
    description: Detects the use of curl or wget to directly query sensitive Kubernetes API endpoints.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
      - execution
    techniques:
      - T1059.004
      - T1069
      - T1552.007
      - T1613
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify direct API access
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for curl/wget process executions containing /api/v1/ in command line
      technique_id: T1552.007
      data_needed:
        - Process command line
      priority: medium
      confidence: high
      disposition: convert_to_detection
updates:
  - at: "2026-09-19T13:13:03Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_kubernetes_direct_api_request_via_curl_or_wget.toml
---

Adversaries often attempt to interact with Kubernetes environments by directly querying the Kubernetes API server using native command-line tools like curl or wget. This technique allows attackers to evade monitoring associated with legitimate Kubernetes administration tools like kubectl and facilitates the discovery of cluster resources, including pods, deployments, and sensitive configurations such as secrets and config maps. This unauthorized interaction is used for both situational awareness within the target cluster and the direct exfiltration of sensitive material. Detecting these attempts requires visibility into process execution command lines that specifically target sensitive paths within the Kubernetes API. The activity poses a significant risk to the confidentiality and integrity of the containerized environment.

## Attack Chain

1. Attacker gains initial execution capability within a container or a host with network access to the internal Kubernetes API.
2. Attacker performs reconnaissance to identify the local network configuration and the address of the Kubernetes API server.
3. Attacker uses a native utility, such as curl or wget, to initiate an HTTP request directed at the Kubernetes API.
4. The request is crafted to target sensitive endpoints such as /api/v1/secrets or /apis/rbac.authorization.k8s.io/.
5. The API server processes the request, potentially returning sensitive configuration data or credentials if authentication is not strictly enforced or if the attacker has obtained a token.
6. Attacker exfiltrates the discovered secrets or metadata back to their infrastructure or uses the discovered information for lateral movement within the cluster.

## Impact

Successful exploitation of this technique can lead to the exposure of sensitive cluster secrets, service account tokens, and configuration data. This unauthorized access enables further compromise, including lateral movement, privilege escalation, and potential takeover of cluster-level resources, impacting the security posture of the entire containerized infrastructure.

## Recommendation

1. Deploy the provided Sigma rule to detect suspicious process command lines that indicate direct interaction with Kubernetes API endpoints.
2. Baseline authorized tools and scripts (such as CI/CD pipelines or automated health checks) that require access to the API to reduce false positives.
3. Enforce strict Kubernetes RBAC and network policies to restrict internal pod access to the API server.
4. Monitor Kubernetes audit logs for anomalous or unauthorized API requests, correlating them with process execution telemetry on the source host.
