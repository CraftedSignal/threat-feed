---
title: Unauthenticated Arbitrary File Read and Write in TEN Framework
slug: 2026-09-ten-framework-rce
description: TEN Framework version 0.11.71 contains unauthenticated file read and write vulnerabilities in its API endpoints, enabling remote code execution via file system manipulation.
date: "2026-09-04T15:26:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ten:framework:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - webserver
vendors:
  - TEN
products:
  - TEN Framework (0.11.71)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: TEN Framework 0.11.71 contains unauthenticated arbitrary file read and write vulnerabilities in the TMAN Designer file-content API endpoints.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Exploitation of this vulnerability allows attackers to... write malicious content to system paths, potentially leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-85688
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85688
rules:
  - title: Detects CVE-2026-85688 Exploitation - API File Read/Write Attempt
    description: Detects unauthenticated POST or PUT requests to TEN Framework TMAN Designer file-content API endpoints.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for API access attempts to /api/designer/v1/file-content.
      owner: Detection Engineering
      due: 24h
      evidence: Source document identifies these endpoints as the exploit vector.
  hunt_leads:
    - lead: Search logs for unauthorized POST or PUT requests to /api/designer/v1/file-content from external IPs.
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated access via these endpoints.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the TEN Framework TMAN Designer API.
      owner: IT Operations
      addresses: CVE-2026-85688
      evidence: Source identifies vulnerability in TMAN Designer API.
---

TEN Framework version 0.11.71 is impacted by a critical vulnerability (CVE-2026-85688) affecting the TMAN Designer component. The vulnerability resides in the /api/designer/v1/file-content API endpoints, which fail to properly validate requests. This flaw allows unauthenticated attackers to perform arbitrary file reads and writes on the underlying host system. By sending maliciously crafted POST or PUT requests to these endpoints, an attacker can read sensitive configuration files or overwrite system files. Successful exploitation enables remote code execution through methods such as modifying SSH authorized_keys, appending malicious cron jobs, or injecting code into executable graph files used by the framework. Given the CVSS score of 9.8, this vulnerability poses a severe risk to any internet-exposed TEN Framework instances.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing TEN Framework TMAN Designer instances.
2. Attacker crafts a malicious HTTP POST request targeting the /api/designer/v1/file-content endpoint.
3. Attacker uses the vulnerability to read local system configuration files to map internal paths.
4. Attacker constructs a malicious payload, such as a reverse shell script or an SSH public key.
5. Attacker sends an HTTP PUT request to the same endpoint to overwrite a sensitive system file (e.g., /home/user/.ssh/authorized_keys).
6. If targeting cron, the attacker writes a malicious job definition to /etc/cron.d/ or /var/spool/cron/.
7. The system executes the injected code or grants unauthorized access, completing the compromise.

## Impact

Successful exploitation leads to full system compromise of the server running TEN Framework. Attackers gain the ability to exfiltrate sensitive data, establish persistent backdoors via SSH keys or cron jobs, and execute arbitrary code with the privileges of the service user. This vulnerability affects all deployments of TEN Framework 0.11.71 and carries a high risk of automated exploitation by threat actors scanning for vulnerable web applications.

## Recommendation

* Immediately upgrade all instances of TEN Framework to a patched version once released by the vendor.
* Restrict network access to the TMAN Designer API endpoints to trusted administrative IP addresses using a firewall or ingress controller.
* Audit server logs for unauthorized HTTP POST or PUT requests to /api/designer/v1/file-content.
* Implement integrity monitoring on critical system files like /home/*/.ssh/authorized_keys and /etc/cron.* to detect unauthorized modifications.
