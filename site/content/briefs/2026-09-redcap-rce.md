---
brief_id: brief-2026-09-redcap-rce
event_id: brief-2026-09-redcap-rce
revision: 2
activity_at: "2026-11-19T16:43:11Z"
revision_history:
  - revision: 2
    at: "2026-11-19T16:43:11Z"
    checksum: sha256:0f8c0357aec87cc3e8ed9893ec5f253bb0ed4f950209cb66507948fcebbe4708
    summary: exploited:true; KEV CVE-2026-90817
    changed_fields:
      - cve_verification
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - rules
      - updates
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-90817
title: Critical Remote Code Execution in Vanderbilt REDCap via Survey Passthru
slug: 2026-09-redcap-rce
description: A critical unauthenticated RCE vulnerability (CVE-2026-90817) in Vanderbilt REDCap allows attackers to bypass routing restrictions through the '__passthru' parameter, enabling unauthorized access to administrative controllers.
date: "2026-09-24T10:11:59Z"
lastmod: "2026-11-19T16:41:11Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-09-24T10:11:59Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:vanderbilt:redcap:*:*:*:*:*:*:*:*
tags:
  - cve-2026-90817
  - remote-code-execution
  - vulnerability
  - webserver
vendors:
  - Vanderbilt
products:
  - REDCap
product_versions:
  - product: REDCap
    range: '>= 13.3.0'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can abuse __passthru (survey passthrough) routing to reach unintended controllers (e.g. Data Import), then trigger unsafe file-path / stream handling → RCE.
    confidence_band: high
cve_verification:
  CVE-2026-90817:
    status: verified
    source: nvd
    checked_at: 2026-11-19T16:41:11.002705804Z
cves:
  - id: CVE-2026-90817
    cvss: 9.8
    epss: 0.25187
    kev: true
    kev_status: "true"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90817
  - https://www.securifera.com/advisories/
  - https://sploitus.com/exploit?id=48646C7B-3133-5AEB-A02C-28B48D701D6D
  - https://www.cve.org/CVERecord?id=CVE-2026-90817
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all REDCap instances to version 16.0.49 LTS, 17.3.10 LTS, or 17.4.4 Standard.
      owner: IT Operations
      due: 24h
      evidence: Fixed versions are documented in the exploit PoC repository.
  hunt_leads:
    - lead: Search logs for HTTP GET/POST requests containing the __passthru parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit PoC code uses this parameter to probe vulnerable targets.
updates:
  - at: "2026-11-19T16:41:11Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-90817
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-90817
---

## Overview

CVE-2026-90817 is a critical remote code execution (RCE) vulnerability affecting Vanderbilt REDCap versions 13.3.0 and later. The vulnerability stems from an insecure implementation of the survey passthrough ('__passthru') routing mechanism. By manipulating this parameter within a public survey context, an unauthenticated attacker can force the application to route requests to restricted internal controllers, specifically the Data Import module. This improper routing, combined with insecure file-path or stream handling, allows for the execution of arbitrary code on the underlying web server. While the vulnerability requires a valid public survey hash ('s=') to trigger the full chain, the widespread use of public-facing surveys in academic and clinical research environments significantly increases the attack surface. Organizations using REDCap are strongly urged to patch to the identified LTS or standard releases immediately.

## Impact

The vulnerability carries a CVSS score of 9.8, indicating high potential for full system compromise. If exploited, attackers can gain unauthorized remote code execution, leading to data exfiltration of sensitive research and patient information, lateral movement within the hosting network, and loss of integrity for the affected REDCap research databases. The vulnerability impacts numerous academic, research, and healthcare institutions that rely on REDCap for data collection.

## Recommendation

* Upgrade all affected REDCap instances to the patched versions: 16.0.49 LTS, 17.3.10 LTS, or 17.4.4 Standard, as specified by the vendor.
* Deploy the Sigma rules provided in this brief to detect scanning and exploitation attempts targeting the '__passthru' parameter.
* Monitor web server logs for suspicious HTTP requests containing '__passthru' directed at administrative or data import URI stems.
* Restrict public access to survey endpoints and implement WAF rules to sanitize or block requests containing unusual path traversal or controller manipulation strings.
