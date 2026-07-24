---
title: Anti-Virus Product Reconnaissance via PowerShell or WMI
slug: 2026-07-av-recon-via-powershell
description: This brief details the detection of suspicious PowerShell script execution that targets the discovery of installed anti-virus and anti-spyware products using WMI or PowerShell commands, a common reconnaissance tactic employed by malicious actors to map security applications and potentially evade defenses.
date: "2026-07-24T09:02:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - discovery
  - defense-evasion
  - powershell
  - wmi
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The following analytic detects suspicious PowerShell script execution via EventCode 4104, specifically targeting checks for installed anti-virus products using WMI or PowerShell commands.
    confidence_band: high
references:
  - https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/
  - https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba.
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
  - https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
  - https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/
  - https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
rules:
  - title: Detect Anti-Virus Product Reconnaissance via PowerShell Script Block Logging
    description: Detects suspicious PowerShell script execution, captured by EventCode 4104, that attempts to enumerate installed anti-virus or anti-spyware products using WMI or PowerShell commands. This is a common reconnaissance technique used by attackers to understand and bypass endpoint security.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1592
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This threat brief focuses on the detection of a specific reconnaissance technique where adversaries or malware utilize PowerShell or Windows Management Instrumentation (WMI) to identify installed anti-virus (AV) and anti-spyware products on an endpoint. This activity is typically logged via PowerShell Script Block Logging (EventCode 4104) and is characterized by the execution of scripts containing keywords such as "SELECT," "WMIC," "AntiVirusProduct," or "AntiSpywareProduct." The technique is commonly employed by advanced persistent threat (APT) groups and various malware families (e.g., Maze ransomware, XWorm, Qakbot) to gain an understanding of the security posture of a compromised system. By mapping the running security applications, attackers can strategize evasion techniques, develop methods to disable or bypass security controls, and ultimately facilitate further malicious activities, leading to deeper compromise and data exfiltration or encryption.

## Attack Chain

1. **Initial Access (Pre-requisite):** An attacker gains initial access to a target system through various means (e.g., spearphishing, exploiting a vulnerability).
2. **Execution:** The attacker executes a PowerShell script on the compromised endpoint.
3. **Reconnaissance Command:** The PowerShell script or command utilizes WMI queries or native PowerShell cmdlets to enumerate installed security products.
4. **Query Execution:** The script issues commands such as `SELECT * FROM AntiVirusProduct` or `WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName`.
5. **Information Gathering:** The executed query returns details about the anti-virus and anti-spyware solutions present on the system.
6. **Defense Evasion Planning:** The attacker collects this information to understand the security landscape of the host, which is then used to plan subsequent actions aimed at evading or disabling detected security software.
7. **Follow-on Malicious Activity:** Based on the reconnaissance, the attacker proceeds with further stages of the attack, such as payload delivery, persistence mechanisms, or exfiltration, tailored to bypass the identified defenses.

## Impact

The successful execution of anti-virus product reconnaissance provides attackers with critical intelligence about a target's defensive capabilities. This information directly enables threat actors to refine their defense evasion strategies, bypass security controls, and prevent detection. If attackers can effectively circumvent security software, the impact includes increased risk of data exfiltration, deployment of ransomware, establishment of persistent access, and broader network compromise. While no specific victim counts or sectors are mentioned for this isolated technique, it is a foundational step in many targeted attacks, facilitating severe outcomes across any targeted organization.

## Recommendation

* **Enable PowerShell Script Block Logging (EventCode 4104)**: Ensure PowerShell Script Block Logging is comprehensively enabled across all Windows endpoints to capture script content that this detection relies on.
* **Deploy the Sigma rules in this brief to your SIEM**: Implement the provided Sigma rule to detect suspicious PowerShell commands targeting AV/AS product reconnaissance using `ScriptBlockText` fields.
* **Tune for environment-specific false positives**: Review the `falsepositives` section of the Sigma rule and create exceptions for known legitimate administrative or security tooling in your environment that might perform similar checks.
