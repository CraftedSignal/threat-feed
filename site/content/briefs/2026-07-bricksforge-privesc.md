---
title: Bricksforge WordPress Plugin Privilege Escalation Vulnerability (CVE-2026-14956)
slug: 2026-07-bricksforge-privesc
description: The Bricksforge plugin for WordPress, in versions up to and including 3.1.8.6, contains a critical privilege escalation vulnerability, CVE-2026-14956, allowing unauthenticated attackers to register new administrator accounts by manipulating the 'fieldIds' parameter in Pro Forms registration actions, leading to full compromise of the WordPress site.
date: "2026-07-17T02:19:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - vulnerability
  - webserver
vendors:
  - Bricksforge
products:
  - Bricksforge plugin (up to 3.1.8.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Bricksforge plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 3.1.8.6. This is due to improper validation of the fieldIds parameter in the Pro Forms registration action, which allows attacker-supplied field IDs to be added to the trusted form-field whitelist. This makes it possible for unauthenticated attackers to register a new administrator account.
    confidence_band: high
cves:
  - id: CVE-2026-14956
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14956
---

A critical privilege escalation vulnerability, tracked as CVE-2026-14956, has been identified in the Bricksforge plugin for WordPress, affecting all versions up to and including 3.1.8.6. This flaw originates from insufficient validation of the `fieldIds` parameter within the Pro Forms registration action, enabling attackers to inject arbitrary field IDs into a trusted form-field whitelist. Unauthenticated attackers can exploit this by sending a specially crafted request to a publicly accessible Bricksforge Pro Forms registration form that is configured with the User Registration action. Successful exploitation allows the attacker to create a new administrator account, granting them complete control over the compromised WordPress website. This vulnerability poses a severe risk to organizations utilizing the Bricksforge plugin, as it can lead to unauthorized access, data manipulation, website defacement, and further malicious activities.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site utilizing the Bricksforge plugin and the Pro Forms feature.
2. The attacker confirms the presence of a publicly accessible Bricksforge Pro Forms element configured with the User Registration action.
3. The attacker crafts an HTTP POST request targeting the identified Pro Forms registration endpoint.
4. The crafted request includes a maliciously manipulated `fieldIds` parameter in the request body or query string.
5. The `fieldIds` parameter is populated with an attacker-supplied ID that, due to the improper validation flaw, is added to the plugin's trusted form-field whitelist.
6. This allows the attacker to specify a privileged role, such as "administrator," for the new user account being registered through other form parameters.
7. The attacker submits the crafted POST request to the Bricksforge Pro Forms registration form.
8. The vulnerable Bricksforge plugin processes the request, bypasses intended security controls, and successfully creates a new user account with administrator privileges on the WordPress site.

## Impact

Successful exploitation of CVE-2026-14956 results in a complete compromise of the affected WordPress website. Unauthenticated attackers gain full administrator privileges, enabling them to execute arbitrary code, manipulate website content, exfiltrate sensitive data, install backdoors, and launch further attacks. This can lead to significant reputational damage, operational disruption, and potential legal or compliance repercussions for the affected organization. The broad applicability to unauthenticated attackers and the ease of registering an admin account make this a high-severity threat with potentially widespread consequences for WordPress installations running vulnerable versions of the Bricksforge plugin.

## Recommendation

* Patch CVE-2026-14956 immediately by updating the Bricksforge plugin to a version beyond 3.1.8.6 as soon as a fix becomes available.
* Review all Bricksforge Pro Forms configurations on your WordPress sites to ensure that any publicly accessible registration forms are not configured with the User Registration action, or disable them until a patch is applied.
* Monitor web server logs for suspicious HTTP POST requests directed at registration endpoints, particularly those containing the `fieldIds` parameter with unusual or unexpected values.
