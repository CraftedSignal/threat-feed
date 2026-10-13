---
title: Stored XSS in Froxlor via Malicious Theme Configuration
slug: 2026-10-froxlor-xss
description: Froxlor versions 2.0.0 through 2.3.13 are vulnerable to stored cross-site scripting (XSS) via the customer theme setting, allowing authenticated customers to compromise administrator sessions.
date: "2026-10-13T14:39:08Z"
lastmod: "2026-10-13T14:39:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:froxlor:froxlor:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - vulnerability
  - linux
vendors:
  - Froxlor
products:
  - Froxlor (2.0.0-2.3.13)
  - Froxlor (< 2.3.14)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated customers to inject HTML and JavaScript by setting a malicious theme value via customer_index.php.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Script executes when an administrator views the customer overview... letting attackers abuse the CSRF token to create administrator accounts.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can embed newline characters that the REBUILD_NSSUSERS cron writes unsanitized into /var/lib/extrausers/group, creating privileged group entries for local privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-109960
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109960
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109961
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Froxlor to version 2.3.14 or later
      owner: IT Operations
      due: 24h
      evidence: Source states Froxlor 2.0.0 before 2.3.14 contains the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade Froxlor to 2.3.14
      owner: IT Operations
      addresses: CVE-2026-109960
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-10-13T14:39:16Z"
    level: L2
    summary: added coverage for Froxlor (< 2.3.14)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109961
---

Froxlor versions from 2.0.0 up to, but not including, 2.3.14 are susceptible to a stored cross-site scripting (XSS) vulnerability. The vulnerability resides in the `customer_index.php` component, where the application fails to properly sanitize the theme configuration value submitted by authenticated customers. An attacker with standard customer access can inject malicious HTML and JavaScript payloads into their theme settings. When an administrator subsequently views the customer overview page with the 'Theme' column enabled, the payload executes within the context of the administrator's session. This allows the attacker to perform actions as the administrator, including creating new unauthorized administrator accounts or altering sensitive server configurations.

## Impact

Successful exploitation allows for complete takeover of the administrative interface. Attackers can escalate privileges by creating new administrator accounts or modify underlying server settings, potentially leading to total system compromise. This vulnerability specifically affects environments hosting multiple customers where standard user accounts are accessible to the attacker.

## Recommendation

* Update Froxlor to version 2.3.14 or later immediately to patch the input sanitization flaw in `customer_index.php`.
* Monitor administrative access logs for suspicious account creation or configuration changes performed shortly after viewing the customer overview module.
* Restrict administrative access to the customer overview page until the patch is applied.
