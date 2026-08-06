---
title: Authentication Bypass in Dinky SysConfigController
slug: 2026-08-dinky-auth-bypass
description: Dinky v1.2.5 and development builds contain an authentication bypass in the SysConfigController.getAll handler, allowing unauthenticated remote attackers to retrieve cleartext system credentials and service tokens.
date: "2026-08-06T23:31:20Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Apache
products:
  - Dinky (1.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any remote unauthenticated caller who can reach the Dinky HTTP port receives the full live system configuration.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: Any remote unauthenticated caller who can reach the Dinky HTTP port receives the full live system configuration.
    confidence_band: high
cves:
  - id: CVE-2026-70559
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70559
rules:
  - title: Detects CVE-2026-70559 Exploitation - Unauthorized GET Request to SysConfig
    description: Detects unauthenticated GET requests to the /api/sysConfig/getAll endpoint which triggers the credential leak.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1082
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block access to port 8888 for external IPs
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated access via the network is the primary vector
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /api/sysConfig/getAll via webserver configuration
      owner: IT Operations
      addresses: CVE-2026-70559
      evidence: Vulnerability allows unauthenticated access to the endpoint
---

Dinky v1.2.5 and development branch builds contain an authentication bypass vulnerability (CVE-2026-70559) within the SysConfigController.getAll handler. The vulnerability stems from a method-level @SaIgnore annotation that overrides the class-level @SaCheckLogin, effectively disabling the Sa-Token interceptor for the /api/sysConfig/getAll endpoint. Consequently, any remote unauthenticated caller with network access to the Dinky HTTP port (default 8888) can trigger a parameterless GET request to retrieve the full live system configuration.

The leaked configuration data contains sensitive cleartext credentials, including LDAP passwords, OSS access/secret keys, DolphinScheduler tokens, and the internal Dinky service token. This exposure is particularly critical as it reveals the dinkyToken, which is the primary authentication gate for the /download/uploadFromRsByLocal endpoint, facilitating downstream arbitrary file write attacks. The issue affects the v1.2.5 release and the current development head (63b5a5a).

## Impact

Successful exploitation allows unauthenticated attackers to harvest highly sensitive third-party integration credentials and administrative service tokens. Access to these credentials facilitates deeper lateral movement within the environment and persistent access to backend services such as LDAP servers, Object Storage, and job scheduling platforms. Furthermore, the leakage of the internal dinkyToken directly enables exploitation of arbitrary file write vulnerabilities, leading to potential remote code execution on the Dinky server.

## Recommendation

- Restrict network access to the Dinky HTTP port (8888) to trusted IP ranges only via host-based or network firewalls to prevent unauthorized access to /api/sysConfig/getAll.
- Audit all third-party credentials (LDAP, OSS, DolphinScheduler) that were stored in the Dinky Settings Center, as these are considered compromised.
- Implement monitoring on the /api/sysConfig/getAll endpoint to detect unauthorized GET requests from non-admin internal segments.
- Review and rotate the dinkyToken immediately if the Dinky instance is network-accessible.
