---
title: Reflected Cross-Site Scripting Vulnerability in Frappe ERPNext
slug: 2026-10-frappe-xss
description: Frappe ERPNext versions before 14.92.1 and 15.x before 15.83.0 are susceptible to reflected XSS, allowing unauthenticated attackers to execute arbitrary JavaScript in authenticated sessions.
date: "2026-10-13T00:31:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:frappe:erpnext:*:*:*:*:*:*:*:*
vendors:
  - Frappe
products:
  - ERPNext (< 14.92.1, < 15.83.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Remote attackers can lure a logged-in user into opening a crafted URL to run injected script and take over the victim's account.
    confidence_band: high
cves:
  - id: CVE-2025-71432
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71432
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all ERPNext instances to version 14.92.1 or 15.83.0.
      owner: IT Operations
      due: 48h
      evidence: CVE-2025-71432 remediation requires patching to specified versions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade ERPNext to 14.92.1 or 15.83.0.
      owner: IT Operations
      addresses: CVE-2025-71432
      evidence: Source advisory
---

Frappe ERPNext versions prior to 14.92.1 and 15.x before 15.83.0 contain a reflected cross-site scripting (XSS) vulnerability. The issue stems from insufficient input validation on a specific web page within the ERPNext application. This flaw allows remote, unauthenticated attackers to craft malicious URLs containing injected JavaScript. If an authenticated user is coerced into interacting with these crafted URLs, the injected script executes within the victim's browser session. Successful exploitation enables unauthorized actions on behalf of the victim, potentially leading to full account takeover, session token theft, or data exfiltration.

## Impact

The vulnerability poses a high risk to organizations utilizing ERPNext for business operations. If exploited, an attacker could gain administrative control over an affected user's account, access sensitive business data, or perform unauthorized transactions within the ERP system. Because this is a reflected XSS attack, the scope is limited to users that can be social-engineered into clicking the malicious link.

## Recommendation

- Upgrade to Frappe ERPNext version 14.92.1 or later, or 15.83.0 or later to patch CVE-2025-71432.
- Implement Content Security Policy (CSP) headers to restrict the execution of unauthorized inline scripts and mitigate the impact of potential XSS vulnerabilities.
- Ensure users are educated on the risks of clicking unsolicited or suspicious links, especially when logged into critical business applications.
