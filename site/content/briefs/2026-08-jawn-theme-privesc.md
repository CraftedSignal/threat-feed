---
title: Unauthenticated Privilege Escalation in Jawn WordPress Theme
slug: 2026-08-jawn-theme-privesc
description: The Jawn WordPress theme, versions 1.4.2 and earlier, is vulnerable to a critical unauthenticated privilege escalation attack due to incorrect privilege assignment.
date: "2026-08-25T08:06:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - MVPThemes
products:
  - Jawn
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to elevate their privileges to that of an administrator.
    confidence_band: high
cves:
  - id: CVE-2026-78477
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78477
  - https://patchstack.com/database/wordpress/theme/jawn/vulnerability/wordpress-jawn-theme-1-4-2-privilege-escalation-vulnerability
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/e0642c85-ee01-497c-8dc3-42e3ffc02995?source=cve
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update Jawn theme to version 1.4.3 or higher.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-78477 indicates vulnerability in all versions up to 1.4.2.
  hunt_leads:
    - lead: Search for unauthorized new administrator accounts created in the WordPress database.
      technique_id: T1098
      data_needed:
        - WordPress wp_users and wp_usermeta tables
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Privilege escalation leads to admin role assignment.
---

The Jawn theme for WordPress is impacted by a critical privilege escalation vulnerability (CVE-2026-78477), which allows unauthenticated remote attackers to gain administrative access to affected WordPress installations. Identified as an instance of CWE-266 (Incorrect Privilege Assignment), this flaw affects all versions of the theme up to and including 1.4.2. Because WordPress themes often handle user registration or profile updates, improper validation of input during these processes can lead to the elevation of a standard or unauthenticated user to an administrative role. This vulnerability presents a severe risk to site integrity, enabling full control over the WordPress content management system, arbitrary file uploads, and further compromise of the underlying server infrastructure. Defenders should prioritize updating the Jawn theme to a version beyond 1.4.2 immediately.

## Attack Chain

1. Attacker performs reconnaissance to identify websites utilizing the Jawn theme (e.g., checking theme metadata or CSS paths).
2. Attacker probes the WordPress instance to identify endpoints handling user profile registration or profile updates provided by the Jawn theme.
3. Attacker sends a crafted HTTP request to a vulnerable theme-specific registration or update endpoint.
4. The theme fails to properly validate the authorization level of the request or the parameters provided.
5. The server processes the malicious payload, which includes parameters forcing a change in the user's privilege level.
6. The backend application updates the WordPress database, elevating the attacker's account to the administrator role.
7. Attacker uses administrative credentials to install malicious plugins, exfiltrate data, or execute code on the host server.

## Impact

Successful exploitation of this vulnerability grants the attacker full administrative control over the affected WordPress site. This can result in complete site compromise, leading to unauthorized content modification, the injection of malicious scripts (e.g., web shells or browser redirectors), user data exfiltration, and potential pivot points into the broader network environment if the underlying server is not properly segmented.

## Recommendation

* Update the Jawn theme to the latest available version (beyond 1.4.2) immediately to mitigate the underlying code flaw.
* Audit user account activity for unauthorized changes in privilege levels or anomalous account creation occurring after the installation of the Jawn theme.
* Ensure WordPress sites are configured with the principle of least privilege for theme and plugin file permissions to limit the impact of post-exploitation administrative access.
