---
title: Multiple Vulnerabilities in Schneider Electric NetBotz 5 750/755
slug: 2026-09-netbotz-vulnerabilities
description: Schneider Electric NetBotz 5 750 and 755 devices are affected by OS command injection and Hibernate SQL injection vulnerabilities, enabling unauthorized code execution and database manipulation.
date: "2026-09-17T17:11:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - ics
  - ot
  - cve-2026-13336
  - cve-2026-13337
vendors:
  - Schneider Electric
products:
  - NetBotz 5 750 (<= 5.5.2)
  - NetBotz 5 755 (<= 5.5.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: OS Command Injection vulnerability exists that could cause execution of Linux Operating system commands.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'SQL Injection: Hibernate vulnerability exists that could allow the injection of a malicious HQL query in the NetBotz database.'
    confidence_band: high
cves:
  - id: CVE-2026-13336
    epss: 0.00617
  - id: CVE-2026-13337
    epss: 0.00179
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-05
  - https://www.se.com/ww/en/product-range/61830-netbotz/#software-and-firmware
  - https://www.cve.org/CVERecord?id=CVE-2026-13336
  - https://www.cve.org/CVERecord?id=CVE-2026-13337
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade NetBotz 5 750/755 firmware to 5.6.0
      owner: IT Operations
      due: 48h
      evidence: Vendor fix provided in SEVD-2026-223-02
  mitigation_plan:
    - priority: immediate
      action: Isolate NetBotz management interfaces from external/internet access
      owner: Network Security
      addresses: CVE-2026-13337
      evidence: General security recommendations in CISA advisory
---

Schneider Electric has identified multiple vulnerabilities affecting the NetBotz 5 750 and 755 security and environmental monitoring products, specifically in firmware versions 5.5.2 and earlier. The vulnerabilities, tracked as CVE-2026-13336 and CVE-2026-13337, present risks of arbitrary code execution and unauthorized data access. CVE-2026-13336 is an OS Command Injection vulnerability that allows for arbitrary code execution when a maliciously modified system backup file is restored. CVE-2026-13337 involves an SQL injection vulnerability within the Hibernate framework, which can be exploited by an attacker with access to the web service interface or web-UI to inject malicious HQL queries. These flaws reside in devices critical for monitoring environmental factors like temperature, humidity, and physical security. Successful exploitation could result in complete device compromise or unauthorized manipulation of the monitoring data collected by the units. Defenders should prioritize applying the vendor-provided firmware update to version 5.6.0.

## Attack Chain

1. Attacker gains network access to the target NetBotz device management interface.
2. For CVE-2026-13337, the attacker authenticates to the web-UI or web-service interface.
3. The attacker crafts a malicious HQL query payload targeting the Hibernate database layer.
4. The payload is injected through the web interface, exploiting the lack of input neutralization.
5. For CVE-2026-13336, the attacker obtains or modifies a valid system backup file with embedded OS commands.
6. The attacker initiates the "restore" function on the NetBotz device using the malicious backup.
7. The device processes the restore, inadvertently executing the embedded OS commands within the Linux environment.
8. The final objective is achieved, resulting in arbitrary code execution or unauthorized database modification.

## Impact

Successful exploitation of these vulnerabilities allows for remote or arbitrary code execution on NetBotz 5 750 and 755 hardware. Because these devices serve as critical environmental and physical security monitors for data centers and manufacturing facilities, compromise leads to the potential for data exfiltration, manipulation of security alerts, and the ability to pivot into wider industrial or information technology networks. The vulnerabilities affect organizations globally across the commercial facilities, critical manufacturing, and information technology sectors.

## Recommendation

1. Upgrade all instances of Schneider Electric NetBotz 5 750/755 to firmware version 5.6.0 immediately.
2. Isolate NetBotz monitoring devices behind firewalls and ensure they are not accessible from the public internet to mitigate the attack vector described in CVE-2026-13337.
3. Implement strict access control lists for the web-UI and web-service interfaces to restrict access to authorized management workstations only.
4. Enforce physical security controls for all NetBotz controllers, including housing units in locked cabinets to prevent tampering or unauthorized backup manipulation.
5. Monitor the integrity of system backup files and restrict the ability to perform system restores to verified administrative personnel.
