---
title: PHP Object Injection in Uncanny Automator WordPress Plugin
slug: 2026-10-uncanny-automator-php-injection
description: Authenticated attackers can exploit a PHP Object Injection vulnerability in Uncanny Automator versions 7.6.1.1 and earlier to achieve arbitrary file deletion via a POP chain.
date: "2026-10-08T02:48:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:uncanny_owl:uncanny_automator:*:*:*:*:*:*:*:*
tags:
  - web-application
  - wordpress
  - cve-2026-82627
vendors:
  - Uncanny Owl
products:
  - Uncanny Automator (<= 7.6.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Uncanny Automator plugin for WordPress is vulnerable to PHP Object Injection via deserialization of untrusted input in versions 7.6.1.1 and earlier.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The additional presence of a POP chain within Uncanny Automator allows attackers to delete arbitrary files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-82627
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82627
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Uncanny Automator to the latest patched version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-82627 requires patch deployment
  mitigation_plan:
    - priority: immediate
      action: Upgrade Uncanny Automator to patched version
      owner: IT Operations
      addresses: CVE-2026-82627
      evidence: Source states versions 7.6.1.1 and earlier are vulnerable
---

Uncanny Automator, a WordPress plugin designed for automation, contains a critical PHP Object Injection vulnerability tracked as CVE-2026-82627. The flaw affects all versions up to and including 7.6.1.1. It arises from the insecure deserialization of untrusted input processed during the execution of automation recipes. 

An attacker requires authenticated access with at least Subscriber-level privileges to initiate the exploit. The attack is contingent upon the presence of specific third-party integration plugins, such as PeepSo, MailPoet, or WPForms, and requires the target to have an automation recipe configured that stores user-controlled data as trigger meta. Leveraging a property-oriented programming (POP) chain present within the plugin codebase, an attacker can bypass standard security controls to delete arbitrary files on the underlying web server, potentially leading to a complete service disruption or further compromise.

## Impact

Successful exploitation allows authenticated users with low-level privileges (Subscriber) to delete critical system or application files on the WordPress server. This could lead to a site going offline, the removal of configuration files, or the destruction of essential plugin data. This vulnerability affects any WordPress environment using the Uncanny Automator plugin combined with supported third-party integrations.

## Recommendation

1. Upgrade the Uncanny Automator plugin to the version released after 7.6.1.1 that contains the patch for CVE-2026-82627.
2. Audit user permissions for WordPress subscribers to ensure that only trusted users have access to features interacting with third-party integration automation recipes.
3. Implement file integrity monitoring (FIM) on the web server to detect unexpected file deletion activity originating from the web application process (e.g., www-data, apache).
