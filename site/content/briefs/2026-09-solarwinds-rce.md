---
title: Unauthenticated Remote Code Execution in SolarWinds Observability Self-Hosted
slug: 2026-09-solarwinds-rce
description: SolarWinds Observability Self-Hosted is vulnerable to unauthenticated remote code execution via insecure deserialization, allowing remote attackers to execute arbitrary code.
date: "2026-09-22T20:40:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:solarwinds:observability_self-hosted:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - solarwinds
vendors:
  - SolarWinds
products:
  - SolarWinds Observability Self-Hosted
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SolarWinds Observability Self-Hosted was found to be affected by an unauthenticated remote code execution vulnerability stemming from deserialization of untrusted data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1555
    technique_name: Insecure Deserialization
    evidence: The flaw originates from the insecure deserialization of untrusted data processed by the application.
    confidence_band: high
cves:
  - id: CVE-2026-28325
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28325
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all SolarWinds Observability Self-Hosted instances
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-28325 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Patch SolarWinds Observability Self-Hosted to the version addressing CVE-2026-28325
      owner: IT Operations
      addresses: CVE-2026-28325
      evidence: CVE-2026-28325
---

SolarWinds Observability Self-Hosted contains an unauthenticated remote code execution (RCE) vulnerability identified as CVE-2026-28325. The flaw originates from the insecure deserialization of untrusted data processed by the application when it is configured to operate in a specific communication mode. This vulnerability allows an unauthenticated remote attacker to send specially crafted data to the application, which is then deserialized without adequate validation, leading to the execution of arbitrary code with the privileges of the application process. Given that SolarWinds observability components often run with elevated service accounts on critical infrastructure, successful exploitation could lead to full system compromise. Organizations running self-hosted instances should verify their current configuration against the vulnerability requirements provided by SolarWinds and prioritize patching or disabling the vulnerable communication mode until updates are applied.

## Impact

Successful exploitation of CVE-2026-28325 allows a remote, unauthenticated attacker to execute arbitrary code on the underlying host, potentially leading to unauthorized data access, lateral movement within the network, and full compromise of the affected server.

## Recommendation

- Identify all SolarWinds Observability Self-Hosted instances in the environment.
- Review SolarWinds security advisories to determine if your specific configuration utilizes the vulnerable communication mode.
- Apply patches provided by SolarWinds immediately upon release to remediate CVE-2026-28325.
- Monitor web server and application logs for anomalous POST requests to internal API endpoints that may signify attempts to inject serialized objects.
