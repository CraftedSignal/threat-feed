---
title: Unauthenticated Remote Code Execution in SolarWinds Observability Self-Hosted
slug: 2026-09-solarwinds-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-28324) exists in SolarWinds Observability Self-Hosted due to insufficient integrity checks in non-default, non-secure configurations.
date: "2026-09-22T20:39:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:solarwinds:observability_self-hosted:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - cve-2026-28324
vendors:
  - SolarWinds
products:
  - Observability Self-Hosted
cves:
  - id: CVE-2026-28324
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28324
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit server configurations for non-default settings in SolarWinds Observability
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure regarding non-default configurations
  mitigation_plan:
    - priority: immediate
      action: Review SolarWinds support portal for the specific patch release for CVE-2026-28324
      owner: IT Operations
      addresses: CVE-2026-28324
---

SolarWinds Observability Self-Hosted contains a critical remote code execution vulnerability, tracked as CVE-2026-28324, arising from insufficient integrity checks during processing. This vulnerability allows an unauthenticated, remote attacker to execute arbitrary code on the underlying host. The flaw is specifically present in installations that have been deployed using non-default and non-secure configurations. Given the high CVSS score of 9.8, the vulnerability poses a severe risk to confidentiality, integrity, and availability. Defenders should identify any SolarWinds Observability instances that have deviated from default configuration hardening profiles and verify if integrity controls are properly enforced in their environment.

## Impact

Successful exploitation of CVE-2026-28324 permits an unauthenticated attacker to gain full remote code execution on the target server. This may result in total system compromise, exfiltration of sensitive monitoring data, lateral movement into the internal network, or the deployment of secondary payloads such as ransomware or persistent backdoors. The scope of impact is limited to instances configured in non-default, insecure states.

## Recommendation

Prioritized actions for security and IT operations teams:

- Review all SolarWinds Observability Self-Hosted deployments to identify instances using non-default or hardened configurations that may have disabled mandatory integrity checks.
- Audit logs for unexpected process execution or suspicious network activity originating from the SolarWinds application server.
- Apply security patches or configuration updates provided by SolarWinds to remediate the insufficient integrity check vulnerability identified in CVE-2026-28324.
