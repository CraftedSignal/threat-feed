---
title: New Abuse of ClickOnce Technology for Malware Delivery Mechanics
slug: 2026-07-clickonce-abuse-mechanics
description: Threat actors are increasingly leveraging Microsoft's legitimate ClickOnce application deployment technology to distribute malware, exploiting its streamlined installation process that often bypasses administrative privilege requirements to achieve initial access and execution on Windows endpoints.
date: "2026-07-07T14:53:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - windows
  - endpoint-security
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The user’s deployment request to the end of the deployment... After some prerequisites are met, directly initiates the deployment.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: No elevated privileges required to perform the deployment
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Application Deployment via dfsvc.exe
    description: Detects the execution of the ClickOnce Deployment Support Service (dfsvc.exe) to launch a ClickOnce application, which can be legitimately used but also abused for malware delivery.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

CrowdStrike has identified a growing trend of threat actors abusing Microsoft's ClickOnce technology, a legitimate deployment mechanism designed for distributing applications with minimal user interaction. ClickOnce allows developers to package and deploy applications that users can install and update without requiring administrative privileges, making it a highly attractive vector for malicious purposes. This initial report, Part 1 of a series, delves into the underlying mechanics of ClickOnce application deployment, from how an application is published to its installation on a user's endpoint. Understanding these internal workings is crucial for defenders to anticipate the weaponization methods that simplify the distribution of malware and achieve execution with reduced friction. The technology's user-friendly design, intended for legitimate software, becomes a double-edged sword when leveraged by adversaries to spread malicious payloads efficiently.

## Attack Chain

1.  **Attacker Publishes Malicious ClickOnce App**: The attacker uses development tools (e.g., Visual Studio) to package their malware into a ClickOnce application, generating the necessary deployment manifests (e.g., `.application` file) and associated application files.
2.  **Attacker Hosts Deployment Files**: The attacker hosts the malicious ClickOnce deployment files on an attacker-controlled web server or network share, making them accessible to target victims.
3.  **User Initiates Deployment**: The victim is enticed through social engineering (e.g., phishing emails, malicious websites) to click a link that directly or indirectly triggers the download and execution of the malicious `.application` file.
4.  **ClickOnce Deployment Service Invoked**: Upon the victim attempting to execute the `.application` file, the Windows operating system automatically invokes `dfsvc.exe` (the ClickOnce Deployment Support Service) to handle the deployment process.
5.  **User Confirmation (Optional)**: If the ClickOnce application's publisher cannot be verified (e.g., unsigned or self-signed), the operating system may prompt the user for confirmation to proceed with the application deployment.
6.  **Application Installation/Execution**: Upon user confirmation (if required), `dfsvc.exe` downloads the application's actual payload files and then executes the malicious ClickOnce application, potentially installing it and establishing persistence on the system, often without requiring administrative privileges.
7.  **Malware Payload Delivery**: The executed malicious application then performs its intended malicious functions, such as installing additional malware, establishing command-and-control communications, or initiating data exfiltration.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier for attackers to distribute malware, leading to widespread system compromises across various sectors. The primary impact involves the delivery and execution of arbitrary malicious code on victim endpoints, often without requiring elevated administrative privileges, which circumvents common security controls. This can result in initial access for further exploitation, data exfiltration, ransomware deployment, or the establishment of persistent backdoors. While specific victim counts are not detailed in this report, the ease of deployment facilitated by ClickOnce makes it a highly scalable method for malware distribution, increasing the potential for a large number of compromised systems across any organization whose users are susceptible to social engineering.

## Recommendation

*   Deploy the `Detect ClickOnce Application Deployment via dfsvc.exe` Sigma rule to your SIEM to identify all instances of ClickOnce application launches, which can serve as an early indicator of potential abuse.
*   Ensure `process_creation` logging for `dfsvc.exe` is enabled on all Windows endpoints to provide the necessary telemetry for the rule mentioned above.
*   Educate users about the risks of executing untrusted applications, even those that appear to be legitimate, and the importance of verifying software publishers before clicking "install" prompts.
