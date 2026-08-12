---
title: Hard-coded Authentication Secret in WolfStack
slug: 2026-08-wolfstack-hardcoded-secret
description: WolfStack versions prior to 25.9.2 contain a hard-coded authentication secret that allows unauthenticated remote attackers to bypass authentication and achieve root-level command execution within containerized workloads.
date: "2026-08-12T22:52:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WolfStack
products:
  - WolfStack (< 25.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can bypass authentication by providing this constant secret in the X-WolfStack-Secret header.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute arbitrary commands as root inside any container via the POST /api/containers/{runtime}/{id}/exec endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-73519
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73519
rules:
  - title: Detect CVE-2026-73519 Exploitation - Unauthorized WolfStack API Access
    description: Detects exploitation attempts against CVE-2026-73519 by identifying incoming requests containing the 'X-WolfStack-Secret' header used to bypass authentication.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all WolfStack deployments to version 25.9.2 or later.
      owner: IT Operations
      due: 24h
      evidence: WolfStack before 25.9.2 contains a hard-coded cluster-authentication secret
  mitigation_plan:
    - priority: immediate
      action: Restrict access to WolfStack management ports via network ACLs.
      owner: IT Operations
      addresses: CVE-2026-73519
      evidence: Attackers can reach an affected node's management port
---

WolfStack versions prior to 25.9.2 contain a critical security flaw identified as CVE-2026-73519. The vulnerability stems from a hard-coded cluster-authentication secret, defined as a constant within the source code file 'src/auth/mod.rs' and included in every build. This implementation flaw allows any remote, unauthenticated attacker to bypass the 'require_auth()' authentication gate. By providing the known secret value in the 'X-WolfStack-Secret' HTTP header, an attacker can gain unauthorized access to the node's management port. Once authenticated, an attacker can enumerate running Docker and LXC containers on the target host and execute arbitrary commands with root privileges inside these containers via the '/api/containers/{runtime}/{id}/exec' endpoint. Given the critical severity (CVSS 9.8) and the ease of exploitation, immediate patching is required for all production deployments.

## Attack Chain

1. Attacker performs network reconnaissance to identify exposed WolfStack management ports (typically associated with the product's cluster management functionality).
2. Attacker crafts an HTTP request targeting the management API with the required header 'X-WolfStack-Secret' containing the hard-coded secret value.
3. The 'require_auth()' gate accepts the request, granting the attacker unauthenticated access to the management API.
4. Attacker queries the enumeration endpoint to list all active Docker and LXC container IDs on the target host.
5. Attacker identifies a high-value container (e.g., database or service container) for lateral movement or data extraction.
6. Attacker issues a POST request to '/api/containers/{runtime}/{id}/exec' to inject and execute arbitrary commands.
7. The WolfStack node executes the malicious command payload as root inside the target container.
8. Final objective is achieved via arbitrary command execution and potential container escape or persistence within the containerized environment.

## Impact

Successful exploitation allows for full control over containerized workloads, including data exfiltration, service disruption, and lateral movement within the cluster. Because the 'exec' endpoint facilitates root-level access, attackers can modify container configurations, install persistent backdoors, or potentially exploit container engine vulnerabilities to break out to the host system. This affects any enterprise environment utilizing WolfStack for container orchestration and management.

## Recommendation

* Upgrade all WolfStack instances to version 25.9.2 or later immediately to remove the hard-coded secret.
* Restrict network access to the WolfStack management port to trusted management subnets via firewall rules.
* Deploy the provided Sigma rule to monitor for suspicious requests containing the 'X-WolfStack-Secret' header if immediate patching is not possible.
* Audit logs for unauthorized access patterns against the '/api/containers/' management endpoints.
