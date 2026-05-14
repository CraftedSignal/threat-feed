---
title: Universal Robots Polyscope 5 Unauthenticated Remote Code Execution
slug: 2026-05-universal-robots-rce
description: A vulnerability exists in Universal Robots Polyscope 5 versions prior to 5.25.1, specifically CVE-2026-8153, that could allow an unauthenticated attacker to craft commands that execute code on the robot's OS, leading to full system compromise.
date: "2026-05-14T15:01:54Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - ics
  - rce
  - command injection
  - cve-2026-8153
vendors:
  - Universal Robots
products:
  - Universal Robots Polyscope 5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8153
    cvss: 9.8
    epss: 0.01091
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-17
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-134-17.json
  - https://www.cve.org/CVERecord?id=CVE-2026-8153
  - https://www.universal-robots.com/articles/ur/cybersecurity/cve-2026-8153-command-injection-in-the-polyscope-5-dashboard-server/
rules:
  - title: Detect CVE-2026-8153 Exploitation Attempt via Malicious URI
    description: Detects CVE-2026-8153 exploitation attempt — HTTP request to the Dashboard Server interface containing shell metacharacters indicating command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-8153 Exploitation Attempt via Specific User Agent
    description: Detects CVE-2026-8153 exploitation attempt — HTTP request to the Dashboard Server interface containing shell metacharacters and a specific User-Agent associated with exploit tools.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Universal Robots Polyscope 5 is vulnerable to an OS command injection vulnerability (CVE-2026-8153) in the Dashboard Server interface. This flaw allows an unauthenticated attacker to inject arbitrary commands into the operating system of the robot. The vulnerability affects Polyscope 5 versions prior to 5.25.1. Successful exploitation could lead to complete compromise of the robot's operating system, potentially enabling attackers to disrupt critical manufacturing processes, steal sensitive data, or use the robot as a pivot point for further attacks within the network. This vulnerability was reported to CISA by Vera Mens of Claroty Team82.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable Universal Robots Polyscope 5 instance running a version prior to 5.25.1.
2.  The attacker sends a specially crafted HTTP request to the Dashboard Server interface.
3.  This HTTP request contains malicious OS commands injected into a parameter processed by the Dashboard Server.
4.  The Dashboard Server fails to properly sanitize or neutralize special elements within the injected command.
5.  The vulnerable software executes the injected OS command on the robot's operating system.
6.  The attacker gains arbitrary code execution on the robot's system with the privileges of the affected service.
7.  The attacker could potentially escalate privileges to gain root access.
8.  The attacker can then install malware, steal sensitive information, or manipulate the robot's operations, causing disruption or damage.

## Impact

Successful exploitation of CVE-2026-8153 allows an unauthenticated attacker to execute arbitrary code on the Universal Robots Polyscope 5, potentially leading to full system compromise. This can result in disruption of critical manufacturing processes, theft of proprietary information, or the robot being used as an entry point to compromise other systems on the network. The affected robots are deployed worldwide in Critical Manufacturing sectors.

## Recommendation

*   Immediately update Universal Robots Polyscope 5 to version 5.25.1 or later to patch CVE-2026-8153, as recommended by the vendor. (Universal Robots article: https://www.universal-robots.com/articles/ur/cybersecurity/cve-2026-8153-command-injection-in-the-polyscope-5-dashboard-server/)
*   Apply network segmentation and firewall rules to minimize network exposure for all control system devices, as mentioned in CISA's recommended practices.
*   Deploy the Sigma rule "Detect CVE-2026-8153 Exploitation Attempt via Malicious URI" to detect exploitation attempts targeting the Dashboard Server interface.
