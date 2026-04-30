---
title: CVE-2026-26149 Microsoft Power Apps Spoofing Vulnerability
slug: 2024-02-powerapps-spoofing
description: A spoofing vulnerability exists in Microsoft Power Apps, identified as CVE-2026-26149, potentially allowing an attacker to mislead users or gain unauthorized access.
date: "2026-04-20T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - CVE-2026-26149
  - powerapps
  - spoofing
cves:
  - id: CVE-2026-26149
    cvss: 9
    epss: 0.00058
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26149
rules:
  - title: Detect Suspicious Power Apps Activity
    description: Detects unusual activity within Microsoft Power Apps that may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - windows
  - title: Detect Potential Power Apps Phishing via Referer
    description: Detects potential phishing attempts targeting Power Apps users by analyzing the HTTP Referer header.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-26149 describes a spoofing vulnerability affecting Microsoft Power Apps. While the specifics of exploitation are not detailed in the initial advisory, successful exploitation could allow an attacker to craft deceptive Power Apps or manipulate existing ones to display misleading information, potentially leading to credential theft or other forms of social engineering. The vulnerability's impact is contingent on user interaction, as a user must be tricked into interacting with the spoofed application. Defenders should prioritize understanding the attack vectors and potential impact within their specific Power Apps implementations. Further investigation is needed to fully understand the scope of this vulnerability.

## Attack Chain

1.  Attacker identifies a vulnerable Microsoft Power App deployment.
2.  Attacker crafts a malicious Power App or modifies an existing one to include spoofed content.
3.  Attacker distributes the link to the malicious Power App to a target user, possibly via phishing.
4.  Target user, believing the app is legitimate, interacts with the spoofed elements within the Power App.
5.  The spoofed content prompts the user for sensitive information, such as credentials or personal data.
6.  The user enters their information, unknowingly sending it to the attacker.
7.  The attacker uses the stolen information to gain unauthorized access to other systems or data.

## Impact

Successful exploitation of CVE-2026-26149 could lead to credential theft, data breaches, or unauthorized access to sensitive resources within an organization using Microsoft Power Apps. The scope of the impact depends on the permissions and data accessible by the compromised user. While the exact number of potential victims is unknown, any organization relying on Power Apps is potentially vulnerable. The spoofing could be used in conjunction with other attacks, such as phishing campaigns, to further amplify the damage.

## Recommendation

*   Monitor Power Apps usage for suspicious activity, such as access from unusual locations or attempts to modify app configurations.
*   Implement multi-factor authentication (MFA) to mitigate the risk of credential theft.
*   Educate users on how to identify and avoid phishing attacks targeting Power Apps.
*   Continuously monitor Microsoft's security update guide for further information regarding CVE-2026-26149.
*   Deploy the Sigma rule for detecting suspicious Power Apps activity.
