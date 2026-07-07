---
title: 'New Abuse of the ClickOnce Technology: Part 1'
slug: 2026-07-clickonce-abuse
description: Threat actors are increasingly abusing Microsoft's ClickOnce application deployment technology, which allows for simplified software installation without administrative privileges, to trick users into deploying malicious applications, leveraging its user-friendly mechanism to facilitate malware delivery and execution.
date: "2026-07-07T18:52:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - windows
  - application-deployment
  - abuse
  - initial-access
vendors:
  - Microsoft
products:
  - ClickOnce technology
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The deployment service (dfsvc.exe) responsible for orchestrating the installation and execution process
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has detailed how Microsoft's ClickOnce technology, designed to simplify application deployment and updates, is being abused by threat actors. ClickOnce allows developers to package and distribute applications that users can install and update with minimal interaction and often without requiring administrative privileges. While beneficial for legitimate software distribution, this user-friendly process creates a significant security vulnerability, as it provides an easy vector for threat actors to deliver malware. This initial part of CrowdStrike's series explains the internal workings of ClickOnce, from application publishing to its installation on user endpoints, laying the groundwork for understanding how adversaries can weaponize this legitimate feature for malicious purposes. The article highlights that the 'click once' simplicity, combined with the lack of administrative privilege requirement, makes it an attractive target for initial access and execution of arbitrary code on Windows systems.

## Attack Chain

1.  Attacker develops a malicious application and uses the ClickOnce publishing process within Visual Studio to generate the necessary deployment files (e.e., `.application` manifest, `.manifest`, and application binaries).
2.  The attacker hosts these malicious ClickOnce deployment files on a controlled web server, preparing for distribution.
3.  Victims are lured (e.g., via phishing campaigns, compromised websites, or malvertising) to click a link that points directly to the attacker-controlled `.application` file.
4.  Upon clicking, the user's system downloads the `.application` file, and the legitimate ClickOnce Deployment Support Service (`dfsvc.exe`) initiates the deployment process.
5.  The ClickOnce wizard prompts the user for confirmation to install the application; if the publisher's signature cannot be verified (or if it's spoofed), the user is still prompted.
6.  If the user confirms the installation, `dfsvc.exe` downloads the application components and installs the malicious software into the user's ClickOnce application cache, often without requiring elevated administrative privileges.
7.  The malicious ClickOnce application executes, leveraging its legitimate deployment mechanism to run the attacker's payload (e.g., information stealer, ransomware, backdoor, or other malware).

## Impact

Successful exploitation via malicious ClickOnce applications can lead to a wide range of impacts, including data theft, ransomware deployment, establishment of persistent access, and further compromise of the victim's network. Because ClickOnce deployments often do not require administrative privileges, attackers can bypass some traditional security controls, enabling them to execute malicious code in the context of the logged-on user. The ease of deployment and potential for social engineering through deceptive prompts means a single click can compromise an endpoint, leading to significant financial loss, operational disruption, and reputational damage for affected organizations and individuals. The article does not specify victim counts or targeted sectors in this part.

## Recommendation

*   Monitor process creation events for `dfsvc.exe` activity, as this service orchestrates ClickOnce application deployments.
*   Implement controls to restrict the download and execution of `.application` files from untrusted internet sources.
*   Ensure robust endpoint security solutions are in place to detect malicious payloads launched by ClickOnce applications.
*   Educate users to scrutinize ClickOnce deployment prompts, particularly regarding publisher identity, before confirming any installation.
