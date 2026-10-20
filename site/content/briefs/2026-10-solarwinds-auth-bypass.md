---
brief_id: brief-2026-10-20-solarwinds-auth-bypass
event_id: brief-2026-10-20-solarwinds-auth-bypass
revision: 1
activity_at: "2026-10-20T17:43:38Z"
title: 'SolarWinds Observability Self-Hosted: Broken Authorization Schema (CVE-2026-28328)'
slug: 2026-10-solarwinds-auth-bypass
description: SolarWinds Observability Self-Hosted contains a broken authorization schema vulnerability that permits low-privileged users to access or modify restricted information, leading to unauthorized privilege escalation within the application.
date: "2026-10-20T17:43:38Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified
cpes:
  - cpe:2.3:a:solarwinds:observability_self-hosted:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - vulnerability
  - web-application
vendors:
  - SolarWinds
products:
  - Observability Self-Hosted
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: SolarWinds Observability Self-Hosted was found to be affected by a broken authorization schema that can allow low-privileged users to access and modify information beyond their assigned permissions.
    confidence_band: high
cves:
  - id: CVE-2026-28328
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28328
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch CVE-2026-28328 in SolarWinds Observability Self-Hosted
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-28328 vulnerability advisory
---

SolarWinds Observability Self-Hosted contains a critical broken authorization schema vulnerability, tracked as CVE-2026-28328, which allows authenticated users with low-level privileges to bypass standard access controls. By manipulating specific API requests, an unauthorized actor can gain access to information or perform modifications that are intended to be restricted to administrative or high-privileged roles. This vulnerability poses a significant risk to organizational visibility and infrastructure management integrity, as it facilitates privilege escalation within the self-hosted environment. Defenders should prioritize patching this application, as it provides a mechanism for internal actors or compromised low-privileged accounts to expand their influence and potentially exfiltrate sensitive observability data or alter system configurations.

## Impact

Successful exploitation allows low-privileged users to achieve unauthorized privilege escalation, granting them the ability to read or modify data outside their intended scope. This can lead to the exposure of sensitive network telemetry, service configuration details, and the potential manipulation of alerting or monitoring thresholds, which could be used to mask further malicious activity or cause operational disruption.

## Recommendation

- Apply the latest security patches provided by SolarWinds for the Observability Self-Hosted platform to remediate CVE-2026-28328 immediately.
- Review application access logs for anomalous behavior involving high-privileged API endpoints accessed by accounts typically associated with low-privileged roles.
- Audit current user permission assignments within the SolarWinds Observability interface to ensure the principle of least privilege is strictly enforced while awaiting or applying the patch.
