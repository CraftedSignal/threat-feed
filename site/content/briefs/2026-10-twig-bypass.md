---
title: Craft CMS Twig Sandbox Bypass (CVE-2026-109305)
slug: 2026-10-twig-bypass
description: Craft CMS versions 5.10.2 through 5.10.13 contain a Twig sandbox bypass vulnerability allowing non-admin users with System Messages permissions to execute arbitrary PHP code.
date: "2026-10-12T18:34:41Z"
lastmod: "2026-10-12T18:34:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
vendors:
  - Craft CMS
products:
  - Craft CMS (5.10.2 - 5.10.13)
  - Craft CMS (4.0.0-4.18.6)
  - Craft CMS (5.0.0-5.10.13)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Users with the System Messages permission can supply two-argument callables such as passthru or system in sandboxed templates to execute code as the web user.
    confidence_band: high
cves:
  - id: CVE-2026-109305
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109305
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109308
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Craft CMS to 5.10.14 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109305 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Revoke System Messages permissions from non-authorized users
      owner: IT Operations
      addresses: CVE-2026-109305
      evidence: Source confirms permission level is a prerequisite for exploitation
updates:
  - at: "2026-10-12T18:34:48Z"
    level: L2
    summary: added coverage for Craft CMS (4.0.0-4.18.6) +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109308
---

Craft CMS versions 5.10.2 through 5.10.13 are vulnerable to a Twig sandbox bypass caused by improper validation of the "has some" and "has every" operators. This vulnerability allows an authenticated attacker possessing the "System Messages" permission to bypass the Twig sandbox environment and invoke arbitrary PHP callables. By providing specifically crafted two-argument callables such as 'system' or 'passthru' within sandboxed template fields, an attacker can achieve remote code execution (RCE) in the context of the web server process. This vulnerability is highly critical due to the ease of exploitation by authenticated users with limited privileges, potentially leading to full compromise of the underlying web application environment.

## Impact

Successful exploitation allows for unauthorized code execution on the web server, which can lead to data exfiltration, system-wide compromise, and lateral movement within the hosting infrastructure. The vulnerability affects all Craft CMS installations within the specified version range.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

* Patch Craft CMS to version 5.10.14 or later immediately.
* Audit all user accounts possessing the "System Messages" permission to identify and minimize accounts with excessive privileges.
* Review web server logs for suspicious POST requests containing Twig-related keywords or system command patterns (e.g., system, passthru, exec) submitted via template editing interfaces.
* Implement stricter access controls and monitor template modification activities within the administrative interface.
