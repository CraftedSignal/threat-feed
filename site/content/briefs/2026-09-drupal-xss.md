---
title: Multiple Cross-Site Scripting Vulnerabilities in Drupal
slug: 2026-09-drupal-xss
description: Multiple vulnerabilities discovered in Drupal allow remote attackers to perform cross-site scripting (XSS) attacks by injecting malicious scripts into vulnerable installations.
date: "2026-09-17T13:09:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - web-vulnerability
  - xss
  - patch-management
vendors:
  - Drupal
products:
  - Drupal (11.4.x < 11.4.7)
  - Drupal (11.x < 11.3.17)
  - Drupal (< 10.6.17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: These vulnerabilities allow an attacker to provoke a remote indirect code injection (XSS).
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1196/
  - https://drupal.org/sa-core-2026-013
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade all instances of Drupal to the fixed versions (11.4.7, 11.3.17, or 10.6.17) as specified in SA-CORE-2026-013.
      owner: IT Operations
      addresses: SA-CORE-2026-013
      evidence: Drupal security advisory SA-CORE-2026-013
---

On September 16, 2026, the Drupal security team released security advisory SA-CORE-2026-013, addressing multiple vulnerabilities discovered within the Drupal core software. These vulnerabilities allow an unauthenticated or authenticated remote attacker to perform cross-site scripting (XSS) attacks. By injecting malicious scripts into web pages rendered by the application, an attacker could potentially execute arbitrary code in the context of a user's browser session. The flaws affect several branches of Drupal, including versions 11.4.x prior to 11.4.7, 11.x prior to 11.3.17, and versions prior to 10.6.17. Organizations running affected versions of Drupal are urged to review the vendor's advisory and apply the necessary patches immediately to prevent unauthorized script execution.

## Impact

Successful exploitation of these vulnerabilities enables attackers to inject malicious scripts into the target Drupal site. This can result in session hijacking, unauthorized actions performed on behalf of authenticated users (including administrative accounts), redirection to malicious websites, or the exfiltration of sensitive information displayed on the affected pages. The scope of impact is dependent on the specific user targeted and the privileges they hold within the Drupal application.

## Recommendation

Prioritize the application of security updates provided in the Drupal SA-CORE-2026-013 advisory.
- Upgrade Drupal 11.4.x installations to version 11.4.7 or later.
- Upgrade Drupal 11.x installations to version 11.3.17 or later.
- Upgrade Drupal 10.x installations to version 10.6.17 or later.
- Monitor web server logs for suspicious URL patterns or unexpected script tags being injected into application inputs.
