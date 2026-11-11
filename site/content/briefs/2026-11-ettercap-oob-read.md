---
brief_id: brief-2026-11-11-ettercap-oob-read
event_id: brief-2026-11-11-ettercap-oob-read
revision: 1
activity_at: "2026-11-11T10:51:55Z"
title: 'Ettercap: Out-of-bounds read vulnerability in NTLM authentication (CVE-2026-125405)'
slug: 2026-11-ettercap-oob-read
description: Ettercap through version 0.8.4.1 contains an out-of-bounds read vulnerability in the Parse_NTLM_Auth function, allowing remote attackers to trigger memory disclosure or process crashes via crafted HTTP Authorization headers.
date: "2026-11-11T10:51:55Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment inventory
cpes:
  - cpe:2.3:a:ettercap:ettercap:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ettercap
  - network-security
  - memory-safety
vendors:
  - Ettercap
products:
  - Ettercap (<= 0.8.4.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The vulnerability is triggered when Ettercap processes HTTP Authorization headers during network dissections.
    confidence_band: high
cves:
  - id: CVE-2026-125405
    cvss: 8.1
    epss: 0.00291
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125405
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all instances of Ettercap <= 0.8.4.1 in the environment
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects Ettercap through 0.8.4.1
  hunt_leads:
    - lead: Monitor for anomalous process termination of Ettercap services
      technique_id: T1499
      data_needed:
        - OS process logs (e.g., syslog, Windows Event Log)
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: The advisory notes that the vulnerability can lead to crashing the process.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or patch Ettercap once a fixed version is released
      owner: IT Operations
      addresses: CVE-2026-125405
      evidence: CVE-2026-125405 vulnerability in Parse_NTLM_Auth
---

Ettercap versions through 0.8.4.1 are susceptible to an out-of-bounds read vulnerability within the `Parse_NTLM_Auth()` function located in `src/dissectors/ec_http.c`. The vulnerability stems from improper validation of NTLM message offsets when the tool processes HTTP Authorization headers. A remote attacker can exploit this by sending a specially crafted HTTP request observed by the target Ettercap instance. Depending on the memory layout, this may lead to sensitive information disclosure or a denial-of-service condition via process termination.

## Impact

Successful exploitation allows for the disclosure of arbitrary process memory or a crash of the Ettercap process, potentially disrupting network traffic interception or analysis tasks.

## Recommendation

* Inventory environments where Ettercap 0.8.4.1 or earlier is deployed for network monitoring or security testing.
* Monitor for updates from the Ettercap project and upgrade to the patched version once released.
* Restrict network access to monitoring instances to only trusted sources to mitigate the risk of an attacker sending malicious HTTP headers to be processed by the tool.
