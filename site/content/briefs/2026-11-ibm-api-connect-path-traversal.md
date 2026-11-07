---
brief_id: brief-2026-11-07-ibm-api-connect-path-traversal
event_id: brief-2026-11-07-ibm-api-connect-path-traversal
revision: 1
activity_at: "2026-11-07T05:50:43Z"
title: 'IBM API Connect: Path traversal remote code execution (CVE-2026-17147)'
slug: 2026-11-ibm-api-connect-path-traversal
description: IBM API Connect versions 10.0.8.x and 12.1.x contain a path traversal vulnerability (CVE-2026-17147) that allows an authenticated remote attacker to achieve arbitrary code execution and unauthorized administrative access.
date: "2026-11-07T05:50:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of patch deployment.
cpes:
  - cpe:2.3:a:ibm:api_connect:10.0.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (10.0.8.0 through 10.0.8.12, 12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated remote attacker can exploit this to execute arbitrary code within the application environment.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: '...perform unauthorized administrative actions...'
    confidence_band: high
cves:
  - id: CVE-2026-17147
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17147
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch or upgrade IBM API Connect to a version beyond the affected ranges.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-17147 advisory
  hunt_leads:
    - lead: Monitor API Connect web access logs for path traversal attempts (e.g., ../ sequences) directed at administrative endpoints.
      technique_id: T1210
      data_needed:
        - Web access logs (cs-uri-stem, cs-uri-query)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Path traversal vulnerability (CVE-2026-17147)
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest non-vulnerable version of IBM API Connect.
      owner: IT Operations
      addresses: CVE-2026-17147
      evidence: NVD vulnerability record
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to a path traversal vulnerability (CVE-2026-17147). This flaw enables an authenticated remote attacker to bypass intended file system restrictions, potentially leading to arbitrary code execution and the performance of unauthorized administrative functions within the API Connect environment.

## Impact

Authenticated remote attackers can gain unauthorized administrative control over the API management environment and execute arbitrary code on the underlying infrastructure.

## Recommendation

* Inventory all instances of IBM API Connect within the environment to identify versions 10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2.
* Apply the vendor-provided security patches or upgrade to a remediated version of API Connect as specified in official IBM security advisories.
* Restrict administrative interface access to known, trusted IP addresses and implement robust multi-factor authentication (MFA) to minimize the impact of compromised administrative credentials.
