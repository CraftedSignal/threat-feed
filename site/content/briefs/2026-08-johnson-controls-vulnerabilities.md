---
title: Critical Vulnerabilities in Johnson Controls C-CURE 9000 and victor
slug: 2026-08-johnson-controls-vulnerabilities
description: Multiple vulnerabilities in Johnson Controls C-CURE 9000 and victor application servers, including .NET deserialization (CVE-2026-21655), allow unauthenticated remote code execution and unauthorized information disclosure.
date: "2026-08-11T17:36:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Johnson Controls
products:
  - C-CURE 9000
  - victor Application Server
  - victor
  - victor Web
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of these vulnerabilities could allow an attacker with network access to achieve remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-21655
    epss: 0.00165
  - id: CVE-2026-21653
    epss: 0.00229
  - id: CVE-2026-34496
    epss: 0.00205
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-204-01
  - https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
  - https://www.cve.org/CVERecord?id=CVE-2026-21655
  - https://www.cve.org/CVERecord?id=CVE-2026-21653
  - https://www.cve.org/CVERecord?id=CVE-2026-34496
rules:
  - title: Detect Anomalous Process Execution by CrossFire Server
    description: Detects potentially malicious child processes spawned by SoftwareHouse.CrossFire.Server.exe, which may indicate post-exploitation activity following CVE-2026-21655.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all C-CURE 9000 and victor instances.
      owner: IT Operations
      due: 24h
      evidence: Affected products list.
  mitigation_plan:
    - priority: immediate
      action: Block all inbound traffic to port 8999 from untrusted network segments.
      owner: IT Operations
      addresses: CVE-2026-21655
      evidence: Vendor mitigation guidance.
---

Johnson Controls has disclosed multiple critical vulnerabilities affecting the C-CURE 9000 and victor application server platforms. The most severe flaw, CVE-2026-21655, involves a .NET deserialization vulnerability that allows an unauthenticated attacker on an adjacent network to execute arbitrary code with elevated privileges. Additionally, CVE-2026-21653 permits Server-Side Request Forgery (SSRF) within the victor Web application, while CVE-2026-34496 allows low-privileged users to access restricted pages, including logs and user configurations.

These vulnerabilities impact physical security systems globally, particularly within the Critical Manufacturing sector. Attackers can leverage these flaws to gain full control over the application server process, potentially impacting physical security controls or exfiltrating sensitive system data. Johnson Controls recommends immediate upgrades to C-CURE 9000 v3.20, victor Application Server v4.20, or victor v8.0 to remediate these issues.

## Impact

Successful exploitation of these vulnerabilities could result in complete system compromise, including unauthorized remote code execution on the application server and connected client workstations. An attacker could bypass authentication to view sensitive audit logs and user account information, or pivot within the internal network to gain further control over physical security infrastructure. Given the CVSS score of 9.6, these vulnerabilities represent a significant risk to the integrity and confidentiality of industrial security environments.

## Recommendation

* Upgrade all instances of C-CURE 9000, victor Application Server, and victor to the latest patched versions as specified in the JCI-PSA-2026-07, JCI-PSA-2026-13, and JCI-PSA-2026-16 advisories.
* Implement strict firewall rules to block all unnecessary inbound connections to port 8999 from untrusted or non-essential network segments.
* Deploy IDS/IPS signatures tuned to detect known .NET deserialization exploit payloads (e.g., ysoserial.net patterns) targeting the identified application services.
* Enforce application whitelisting on all application server hosts to restrict the execution of unauthorized binaries.
* Audit the application server process `SoftwareHouse.CrossFire.Server.exe` for anomalous process creation or unauthorized child process execution.
* Disable the `ClientConnectionManager_NF.SynchronousServerNotification` callback interface if it is not required for daily business operations.
