---
title: Rockwell Automation FactoryTalk DataMosaix Stored XSS Vulnerability (CVE-2026-9292)
slug: 2026-07-rockwell-factorytalk-xss
description: An authenticated attacker with high privileges can exploit CVE-2026-9292, a Stored Cross-Site Scripting (XSS) vulnerability, in Rockwell Automation FactoryTalk DataMosaix Private Cloud versions 8.02 and earlier by injecting malicious scripts into the Workflows configuration, leading to execution of malicious JavaScript in other users' browsers and potential account takeover or credential theft.
date: "2026-07-16T16:12:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - ics
  - ot
  - vulnerability
  - cve
vendors:
  - Rockwell Automation
products:
  - FactoryTalk DataMosaix Private Cloud (<=8.02)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of this vulnerability could allow an authenticated attacker to inject malicious scripts on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: This vulnerability can result in the execution of malicious JavaScript when other users access the affected page
    confidence_band: high
cves:
  - id: CVE-2026-9292
    epss: 0.00311
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-09
  - https://www.cve.org/CVERecord?id=CVE-2026-9292
  - https://support.rockwellautomation.com/app/answers/answer_view/a_id/1085012/loc/en_US
  - https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1787.html
---

CISA has released an advisory regarding CVE-2026-9292, a Stored Cross-Site Scripting (XSS) vulnerability impacting Rockwell Automation FactoryTalk DataMosaix Private Cloud versions up to and including 8.02. This vulnerability allows an authenticated attacker with high privileges to inject malicious JavaScript into the "Workflows configuration" within the application. Once injected, these scripts are permanently stored on the server and will execute in the browser of any user who subsequently accesses the affected page. The successful exploitation of this vulnerability could lead to significant consequences, including account takeover, credential theft from affected users, or redirection to malicious websites. The advisory indicates that critical manufacturing and information technology sectors are potentially impacted by this vulnerability, which is deployed worldwide. Rockwell Automation recommends upgrading to DataMosaix Private Cloud version 8.03 or later to remediate the issue.

## Attack Chain

1. An attacker obtains high-privileged authentication credentials for Rockwell Automation FactoryTalk DataMosaix Private Cloud.
2. The authenticated attacker navigates to the Workflows configuration section within the application's interface.
3. The attacker injects malicious JavaScript code into an input field in the Workflows configuration that is vulnerable to improper neutralization of user-supplied input.
4. The application processes and permanently stores the malicious JavaScript code on the server, associating it with the Workflows configuration.
5. A legitimate user, while logged into the FactoryTalk DataMosaix Private Cloud, later accesses the specific application page containing the compromised Workflows configuration.
6. The legitimate user's web browser renders the page, fetching the stored malicious script from the server and executing it in the context of the user's session.
7. The executed malicious JavaScript performs actions such as stealing the user's session cookies, capturing login credentials, or redirecting the user's browser to an attacker-controlled phishing site, potentially leading to account takeover or further compromise.

## Impact

Successful exploitation of CVE-2026-9292 can lead to severe consequences for organizations utilizing Rockwell Automation FactoryTalk DataMosaix Private Cloud. The primary impacts include account takeover of legitimate users, enabling attackers to gain unauthorized access to critical industrial control system (ICS) configurations and data. Additionally, the XSS vulnerability facilitates credential theft, potentially exposing sensitive login information. Attackers could also redirect users to malicious websites, increasing the risk of malware infection or further social engineering attacks. The affected software is used in critical manufacturing and information technology sectors globally, indicating a broad potential impact on industrial operations and data integrity.

## Recommendation

* Immediately patch CVE-2026-9292 by upgrading Rockwell Automation FactoryTalk DataMosaix Private Cloud to version 8.03 or later.
* Review and implement Rockwell Automation's security best practices outlined in their advisory (SD1787 and support article 1085012) for instances that cannot be immediately upgraded.
* Ensure web application logs are configured to capture HTTP request details, including method, URI, and query parameters, to identify potential injection attempts, although specific rules are not provided due to lack of detail.
