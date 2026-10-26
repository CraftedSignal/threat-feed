---
brief_id: brief-2026-10-26-fuji-v-sft-overflow
event_id: brief-2026-10-26-fuji-v-sft-overflow
revision: 1
activity_at: "2026-10-26T07:37:18Z"
title: 'Fuji Electric V-SFT: Stack-based buffer overflow (CVE-2026-107894)'
slug: 2026-10-fuji-v-sft-overflow
description: Fuji Electric V-SFT is vulnerable to a stack-based buffer overflow during the parsing of crafted V7 files, potentially enabling arbitrary code execution.
date: "2026-10-26T07:37:18Z"
lastmod: "2026-10-26T07:37:30Z"
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
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:fujielectric:v-sft:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fuji_electric:v_sft:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
vendors:
  - Fuji Electric
products:
  - V-SFT
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Opening a crafted V7 file may lead to information exposure or arbitrary code execution on the affected product.
    confidence_band: high
cves:
  - id: CVE-2026-107894
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-107895
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107894
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107895
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all hosts running Fuji Electric V-SFT software.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability impacts the V-SFT product.
  hunt_leads:
    - lead: Monitor for V-SFT process execution followed by suspicious child processes (e.g., cmd.exe, powershell.exe, or uncommon network connections).
      technique_id: T1203
      data_needed:
        - Endpoint process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows arbitrary code execution upon opening a malicious file.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor security patches for CVE-2026-107894 once released.
      owner: IT Operations
      addresses: CVE-2026-107894
      evidence: NVD advisory identifies a vulnerability requiring remediation.
updates:
  - at: "2026-10-26T07:37:30Z"
    level: L2
    summary: added CVE-2026-107895
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-107895
---

Fuji Electric V-SFT contains a stack-based buffer overflow vulnerability identified as CVE-2026-107894. This vulnerability is triggered when the application parses a specially crafted V7 file. Successful exploitation may result in information exposure or arbitrary code execution within the context of the application.

## Impact

Successful exploitation could lead to arbitrary code execution or unauthorized information disclosure.

## Recommendation

- Identify all instances of Fuji Electric V-SFT software within the organization.
- Monitor for unusual file-opening activity or unexpected child processes originating from the V-SFT application process.
- Check with the vendor for the availability of security updates or patches addressing CVE-2026-107894 and deploy them to all affected systems.
