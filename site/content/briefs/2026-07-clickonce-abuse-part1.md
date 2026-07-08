---
title: 'Understanding ClickOnce Technology Abuse: Part 1'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are abusing Microsoft's ClickOnce deployment technology to spread malware, allowing malicious applications to be deployed easily with minimal user interaction and without requiring administrative privileges, ultimately delivering malicious payloads onto user endpoints.
date: "2026-07-08T08:08:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - windows
  - endpoint
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
    evidence: Developers can share one of the ClickOnce deployment files, on which the user would only have to 'click once' to deploy the application. These deployment files can be hosted on the vendor's website, where they introduce their app alongside an 'Install' button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Microsoft's ClickOnce technology, designed for simplified application distribution and updating, is being actively abused by threat actors to spread malware. This deployment mechanism allows developers to package and deliver applications that users can run, install, and automatically update with minimal interaction and without requiring administrative privileges. While intended to streamline legitimate software deployment, its user-friendly nature makes it a "double-edged sword," providing an easy vector for malicious payloads. This initial brief, Part 1 of a two-part series, focuses on the internal workings of ClickOnce technology, detailing the process from application publication to installation on the user's endpoint, laying the groundwork for understanding how adversaries weaponize this feature.

## Attack Chain

1. Threat actors publish a malicious application using the ClickOnce technology, generating ClickOnce deployment files (e.g., `.application` manifest) configured for malware delivery.
2. The malicious ClickOnce deployment files are hosted on attacker-controlled websites or network shares, impersonating legitimate software or updates.
3. A user is socially engineered or lured to click an "Install" button or a link pointing to the malicious ClickOnce deployment file.
4. The user's system downloads the `.application` manifest file and associated application files.
5. The operating system may display a security prompt or confirmation dialog to the user, especially if the publisher's signature is untrusted or missing.
6. The user confirms or bypasses the security prompt, which initiates the ClickOnce deployment process via `dfsvc.exe`.
7. The malicious ClickOnce application is executed on the user's system and optionally installed into the `C:\Users\<user>\AppData\Local\Apps\2.0\` directory, often without requiring administrative privileges.
8. The deployed malicious application proceeds to deliver its payload, leading to unauthorized code execution, system compromise, or further malware installation.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass traditional security controls that rely on administrative privileges for software installation. Successful exploitation can lead to the silent deployment of malware, including but not limited to ransomware, infostealers, or remote access Trojans. Victims face potential data exfiltration, system damage, disruption of operations, and further lateral movement within their networks. The seamless, user-driven nature of ClickOnce deployments makes it an effective initial access and execution vector, increasing the risk of widespread compromise.

## Recommendation

* Enable `process_creation` logging to monitor for suspicious invocations or child processes of `dfsvc.exe`, which is integral to ClickOnce deployments.
* Implement `file_event` logging for the `C:\Users\*\AppData\Local\Apps\2.0\` directory to track the creation and modification of ClickOnce application files, as this is a common installation path.
* Monitor `network_connection` logs for outbound connections initiated by `dfsvc.exe` or applications installed in `C:\Users\*\AppData\Local\Apps\2.0\` to unusual or untrusted external destinations.
