---
title: Authentication Bypass in Vulnity Security Plugin for WordPress
slug: 2026-10-vulnity-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-75903) in the Vulnity Security plugin for WordPress allows unauthenticated attackers to retrieve credentials and gain administrative access via misconfigured Nginx path restrictions.
date: "2026-10-16T08:26:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vulnity_security_project:vulnity_security:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - authentication-bypass
  - cve-2026-75903
vendors:
  - WordPress
products:
  - Vulnity Security plugin (<= 1.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This makes it possible for unauthenticated attackers to retrieve the stored credentials.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: An attacker can ... forge signed REST API requests and log in as an administrator.
    confidence_band: high
cves:
  - id: CVE-2026-75903
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75903
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update Vulnity Security plugin to patched version
      owner: IT Operations
      due: 24h
      evidence: Vulnerability CVE-2026-75903 affects plugin versions 1.4.3 and below
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to the credential file path in Nginx server configuration
      owner: IT Operations
      addresses: CVE-2026-75903
      evidence: Insufficient protection of the delegated-login pairing credential file on Nginx-based installations
---

The Vulnity Security plugin for WordPress (versions 1.4.3 and earlier) is susceptible to an authentication bypass vulnerability. The flaw exists on Nginx-based web server installations where the plugin generates a configuration snippet to secure the delegated-login pairing credential file. Due to an incorrect directory path in the server configuration, the credential file remains accessible to unauthorized users. An attacker can exploit this misconfiguration to retrieve the sensitive credentials, forge signed REST API requests, and authenticate as an administrative user. This vulnerability impacts the security of any WordPress installation utilizing the plugin's delegated-login feature on Nginx, potentially leading to a full site takeover.

## Impact

Successful exploitation allows an unauthenticated remote attacker to gain administrative access to the affected WordPress installation. This enables the attacker to modify site content, install malicious plugins, exfiltrate database information, or pivot further into the underlying hosting infrastructure. As the vulnerability resides in a commonly used security-focused plugin, it poses a significant risk to the integrity and confidentiality of targeted WordPress deployments.

## Recommendation

* Immediately update the Vulnity Security plugin to a version addressing CVE-2026-75903.
* Audit Nginx configuration files on WordPress servers for any directives granting read access to the directory containing the plugin's delegated-login pairing credential file.
* Implement access control restrictions in the Nginx configuration to deny all external requests to the identified credential storage path.
