---
title: Fluent Forms Pro Add On Pack Vulnerable to PHP Object Injection (CVE-2026-15962)
slug: 2026-07-fluentforms-php-object-injection
description: An authenticated attacker with Subscriber-level access or higher can exploit a PHP Object Injection vulnerability in the Fluent Forms Pro Add On Pack plugin for WordPress, affecting versions up to and including 6.2.6. This deserialization of untrusted input, when combined with a POP chain, allows attackers to change user passwords and potentially achieve administrator account takeover. Exploitation is contingent on user update integration being enabled and a user meta field being mapped.
date: "2026-07-26T02:17:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - php-object-injection
  - deserialization
  - rce
  - privilege-escalation
vendors:
  - Fluent Forms
  - WordPress
products:
  - Fluent Forms Pro Add On Pack plugin <= 6.2.6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Fluent Forms Pro Add On Pack plugin for WordPress is vulnerable to PHP Object Injection... This makes it possible for authenticated attackers... to inject a PHP Object.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: vulnerable to PHP Object Injection... via deserialization of untrusted input. The additional presence of a POP chain allows attackers to change user passwords and potentially take over administrator accounts.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The additional presence of a POP chain allows attackers to change user passwords and potentially take over administrator accounts.
    confidence_band: high
cves:
  - id: CVE-2026-15962
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15962
---

The Fluent Forms Pro Add On Pack plugin for WordPress, in all versions up to and including 6.2.6, is susceptible to a critical PHP Object Injection vulnerability, tracked as CVE-2026-15962. This flaw arises from the insecure deserialization of untrusted user input, making it possible for authenticated attackers with Subscriber-level access or higher to inject a malicious PHP object. When specific conditions are met - namely, user update integration is enabled and a user meta field is mapped - the vulnerability can be chained with a Property-Oriented Programming (POP) gadget to change user passwords, leading to potential administrator account takeover. This vulnerability poses a significant risk to the integrity and confidentiality of affected WordPress sites, allowing attackers to gain full control over the compromised instance.

## Attack Chain

1. **Initial Access / Authentication:** An attacker obtains or possesses valid credentials for a Subscriber-level or higher user account on a WordPress instance running the vulnerable Fluent Forms Pro Add On Pack plugin.
2. **Configuration Reconnaissance:** The attacker confirms that 'user update integration' is enabled and a 'user meta field' is mapped within the plugin's settings, which are prerequisites for exploitation.
3. **Crafting Malicious Payload:** The attacker prepares a specially crafted serialized PHP object that contains malicious data designed to trigger a specific Property-Oriented Programming (POP) chain within the plugin's or WordPress's codebase.
4. **Submission of Malicious Data:** The crafted serialized PHP object is sent to a vulnerable Fluent Forms Pro Add On Pack plugin endpoint, typically via an authenticated HTTP POST request to a form processing function expecting serialized data.
5. **Insecure Deserialization:** The plugin receives the untrusted, serialized PHP object and proceeds to deserialize it without proper validation or sanitization, initiating the PHP Object Injection.
6. **POP Chain Execution:** The injected object's methods and properties are invoked through the POP chain, allowing the attacker to execute arbitrary actions within the context of the WordPress application.
7. **Privilege Escalation:** The POP chain execution manipulates critical application data or functions, specifically targeting the ability to change passwords of arbitrary users, including administrator accounts.
8. **Account Takeover:** With the administrator account's password changed, the attacker gains full administrative control over the WordPress site, enabling further compromise, data theft, or website defacement.

## Impact

Successful exploitation of CVE-2026-15962 allows authenticated attackers to perform PHP Object Injection, which, when combined with a Property-Oriented Programming (POP) chain, can lead to severe consequences. The primary impact is the ability to change user passwords, including those of administrator accounts. This directly results in full administrator account takeover of the affected WordPress site, granting the attacker complete control over the website's content, data, and configuration. Such access can lead to data exfiltration, website defacement, injection of malicious code, or use of the compromised site for further attacks.

## Recommendation

* Immediately update the Fluent Forms Pro Add On Pack plugin to a version patched for CVE-2026-15962 to remediate the PHP Object Injection vulnerability.
* As a temporary mitigation or if immediate patching is not possible, disable 'user update integration' and unmap any 'user meta fields' within the Fluent Forms Pro Add On Pack plugin settings, as these are necessary conditions for exploitation.
* Regularly review user accounts and their privileges to ensure least privilege is applied, especially for accounts with Subscriber-level access or higher mentioned in the CVE-2026-15962 description.
