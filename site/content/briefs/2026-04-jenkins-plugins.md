---
title: Jenkins Security Advisory Addressing Multiple Plugin Vulnerabilities
slug: 2026-04-jenkins-plugins
description: Jenkins released a security advisory on April 29, 2026, detailing vulnerabilities in Credentials Binding Plugin, GitHub Plugin, GitHub Branch Source Plugin, HTML Publisher Plugin, Matrix Authorization Strategy Plugin, Microsoft Entra ID Plugin, and Script Security Plugin, urging users to apply necessary updates.
date: "2026-04-29T14:40:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - jenkins
  - vulnerability
  - plugin
vendors:
  - Jenkins
  - GitHub
  - Microsoft
products:
  - Credentials Binding Plugin
  - GitHub Plugin
  - GitHub Branch Source Plugin
  - HTML Publisher Plugin
  - Matrix Authorization Strategy Plugin
  - Microsoft Entra ID (previously Azure AD) Plugin
  - Script Security Plugin
references:
  - https://cyber.gc.ca/en/alerts-advisories/jenkins-security-advisory-av26-403
  - https://www.jenkins.io/security/advisory/2026-04-29/#jenkins-security-advisory-2026-04-29
  - https://www.jenkins.io/security/advisories/
rules:
  - title: Detect Suspicious Jenkins Plugin Installation
    description: Detects the installation of plugins from unusual sources, potentially indicating malicious activity.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP 403 Errors Targeting Specific Jenkins Plugins
    description: Detects HTTP 403 errors when attempting to access specific Jenkins plugins, potentially indicating an attempt to exploit a vulnerability.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On April 29, 2026, Jenkins issued a security advisory (AV26-403) addressing vulnerabilities across several plugins. These vulnerabilities affect Credentials Binding Plugin (version 719.v80e905ef14eb_ and prior), GitHub Plugin (version 1.46.0 and prior), GitHub Branch Source Plugin (version 1967.vdea_d580c1a_b_a_ and prior), HTML Publisher Plugin (version 427 and prior), Matrix Authorization Strategy Plugin (versions 2.0-beta-1 to 3.2.9), Microsoft Entra ID (previously Azure AD) Plugin (version 666.v6060de32f87d and prior), and Script Security Plugin (version 1399.ve6a_66547f6e1 and prior). The advisory emphasizes the importance of applying the necessary updates to mitigate potential risks. This broad range of affected plugins highlights the need for Jenkins administrators to promptly review and implement the provided security measures. The Cyber Centre encourages users to review the advisory.

## Attack Chain

Given the nature of the advisory, a generic attack chain is described below. Specific steps depend on the exploited vulnerability in each plugin.

1. An attacker identifies a vulnerable Jenkins plugin version.
2. The attacker crafts a malicious request targeting a specific endpoint of the vulnerable plugin.
3. The request exploits a vulnerability, such as arbitrary code execution, bypass authentication, or cross-site scripting (XSS).
4. The Jenkins server processes the malicious request, leading to unauthorized code execution.
5. The attacker gains access to sensitive information, such as credentials stored within Jenkins.
6. The attacker uses the compromised credentials to access other systems or escalate privileges within the Jenkins environment.
7. The attacker modifies build configurations to inject malicious code into software builds.
8. The attacker compromises software builds and injects malicious code, impacting downstream users of the software.

## Impact

Successful exploitation of these vulnerabilities could lead to unauthorized access to sensitive information, arbitrary code execution on the Jenkins server, and compromise of software builds. This can result in supply chain attacks, data breaches, and reputational damage. The scope of impact depends on the specific vulnerabilities exploited and the access level obtained by the attacker. The Jenkins Security Advisory addresses vulnerabilities in multiple plugins, any of which if exploited, could have significant impacts.

## Recommendation

*   Review the Jenkins Security Advisory 2026-04-29 and identify vulnerable plugins in your environment.
*   Update the Credentials Binding Plugin to a version greater than 719.v80e905ef14eb_.
*   Update the GitHub Plugin to a version greater than 1.46.0.
*   Update the GitHub Branch Source Plugin to a version greater than 1967.vdea_d580c1a_b_a_.
*   Update the HTML Publisher Plugin to a version greater than 427.
*   Update the Matrix Authorization Strategy Plugin to a version greater than 3.2.9.
*   Update the Microsoft Entra ID (previously Azure AD) Plugin to a version greater than 666.v6060de32f87d.
*   Update the Script Security Plugin to a version greater than 1399.ve6a_66547f6e1.
*   Monitor Jenkins webserver logs (category `webserver`, product `linux`) for suspicious activity and unauthorized access attempts after applying the updates.
