---
title: New Abuse of ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse
description: Threat actors are increasingly leveraging Microsoft's legitimate ClickOnce deployment technology to simplify malware distribution, enabling initial access, execution, and potential persistence on user endpoints by tricking users into deploying malicious applications with minimal interaction and often without administrative privileges.
date: "2026-07-06T08:54:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - windows
  - malware-delivery
  - initial-access
vendors:
  - Microsoft
products:
  - ClickOnce Technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor's website, where they introduce their app alongside an “Install” button.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Whether or not the application should be available offline, which determines if the application should only be executed, or also installed into the system
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a growing trend of threat actors abusing Microsoft's ClickOnce deployment technology to facilitate malware distribution. ClickOnce, designed to streamline application installation and updates with minimal user interaction and no administrative privileges, presents a double-edged sword: ease of use for legitimate developers also translates into an attractive vector for malicious actors. This brief, part one of a series, focuses on the inner workings of ClickOnce, detailing its publishing and deployment journey. Attackers can package malicious payloads into ClickOnce applications, host them on controlled infrastructure, and lure victims into initiating the deployment process. This technique allows for efficient malware delivery, execution, and potentially persistence, bypassing traditional installation hurdles and posing a significant risk to endpoint security. Defenders need to understand this mechanism to effectively detect and mitigate such abuses.

## Attack Chain

1.  Attacker packages malicious code into a ClickOnce application through a "publishing" process, configuring it to either execute or install upon deployment.
2.  Attacker hosts the malicious ClickOnce deployment files (e.g., the `.application` manifest file) on a controlled web server or network share.
3.  Attacker socially engineers a victim (e.g., via a phishing email containing a malicious link or a compromised website) to download or click an "Install" button associated with the ClickOnce deployment file.
4.  Victim clicks the malicious link or button, which triggers the download of the `.application` file and initiates the ClickOnce deployment process.
5.  The Windows operating system prompts the user for confirmation, especially if the publisher's signature cannot be verified, to proceed with the application deployment.
6.  Upon user confirmation, the ClickOnce runtime downloads and installs/executes the malicious application, leveraging its self-contained packaging and potentially its self-updating features.
7.  The malicious ClickOnce application executes, gaining initial access to the system and potentially establishing persistence, exfiltrating data, or dropping additional malware payloads.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier for threat actors to deliver malware effectively. If successful, this can lead to widespread infections, as the technology requires minimal user interaction and often bypasses the need for elevated administrative privileges, making it easy for attackers to achieve initial access and execution. The self-updating capability of ClickOnce applications could also allow threat actors to maintain persistence and evolve their payloads without further user intervention. While this brief does not detail specific campaigns or victim numbers, the ease of deployment and legitimate nature of ClickOnce make it a potent vector for various forms of malware, including ransomware, info-stealers, and backdoors, across any sector.

## Recommendation

*   Enable comprehensive process creation logging on Windows endpoints to capture execution of ClickOnce related executables (e.g., `dfsvc.exe`, `rundll32.exe` associated with ClickOnce manifests).
*   Monitor for network connections initiated by unsigned or newly installed applications, especially those originating from temporary ClickOnce deployment directories.
*   Educate users on the risks associated with downloading and executing applications from unverified sources, even if they appear to be legitimate ClickOnce deployments.
