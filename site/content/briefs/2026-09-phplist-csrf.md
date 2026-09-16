---
title: CSRF Vulnerability in phpList Mass Subscriber Removal
slug: 2026-09-phplist-csrf
description: phpList versions prior to 3.6.17 are vulnerable to CSRF, allowing an attacker to force an authenticated administrator to delete or blacklist subscribers without authorization.
date: "2026-09-16T21:58:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:phplist:phplist:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - csrf
  - patch-management
vendors:
  - phpList
products:
  - phpList (< 3.6.17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can induce logged-in administrators to visit crafted pages
    confidence_band: med
cves:
  - id: CVE-2026-92806
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92806
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade phpList to 3.6.17 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-92806 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade phpList to version 3.6.17
      owner: IT Operations
      addresses: CVE-2026-92806
      evidence: NVD vulnerability details
---

phpList versions before 3.6.17 contain a vulnerability in the mass subscriber removal form handler, where the application fails to properly validate cross-site request forgery (CSRF) tokens. This security flaw enables a remote, unauthenticated attacker to induce an already logged-in administrator to perform unauthorized actions by visiting a specially crafted malicious webpage. Upon the administrator's interaction with this page, the application processes the removal and blacklisting of arbitrary subscriber addresses silently and without further authentication or validation prompts. This issue poses a significant risk to subscriber list integrity, potentially resulting in mass data loss or administrative disruption within marketing campaigns. Organizations utilizing affected versions of phpList should prioritize upgrading to version 3.6.17 or later to address the missing token validation mechanism.

## Impact

Successful exploitation results in the unauthorized deletion and permanent blacklisting of subscriber records. This can lead to the loss of entire mailing list segments, disruption of legitimate marketing activities, and administrative burden to recover subscriber data. The vulnerability is particularly severe for organizations relying on phpList for time-sensitive or critical communication.

## Recommendation

* Upgrade all instances of phpList to version 3.6.17 or later immediately to patch CVE-2026-92806.
* Audit access logs for suspicious administrative activity occurring during off-hours or from anomalous IP addresses to identify potential prior abuse.
* Implement strict Content Security Policy (CSP) headers on administrative dashboards to mitigate the impact of malicious cross-site scripting or redirection attempts.
