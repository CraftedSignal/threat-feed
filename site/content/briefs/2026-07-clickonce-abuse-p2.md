---
title: Threat Actors Weaponize ClickOnce Technology for Initial Access, Persistence, and Stealth
slug: 2026-07-clickonce-abuse-p2
description: Threat actors are actively abusing Microsoft's ClickOnce deployment technology, leveraging its user-friendly installation, legitimate process execution, and built-in updating mechanism to achieve initial access, establish persistence through `.appref-ms` files, evade defenses, and maintain remote access without requiring administrative privileges, posing a significant risk to enterprise environments.
date: "2026-07-04T07:39:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - windows
  - defense-evasion
vendors:
  - Microsoft
products:
  - ClickOnce Deployment Technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed... users rarely realize that clicking a webpage button can trigger software installation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: an application reference file (.appref-ms) is dropped at the installation of the application in the Start Menu... By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening... For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems. Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism... This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms File Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce application reference file (.appref-ms) in a user's Windows Startup folder, a common technique for establishing persistence as described in the CrowdStrike report.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

CrowdStrike has observed threat actors actively weaponizing Microsoft's ClickOnce application deployment technology, exploiting its inherent features for initial access, persistence, and defense evasion. This new abuse, highlighted in a June 2026 report, capitalizes on the minimal user interaction required for ClickOnce deployments and a general lack of awareness regarding its security implications. Attackers convince targets to click malicious links or open `.application` files, bypassing traditional security controls like mailbox filters. A key advantage for adversaries is that ClickOnce applications do not require elevated privileges for installation, enabling them to target standard user accounts. Furthermore, the malicious payload executes within legitimate Microsoft process trees, specifically `rundll32.exe` and `dfsvc.exe`, enhancing stealth. The technology's built-in updating mechanism, managed via `.appref-ms` files, also provides a reliable method for maintaining remote access and updating malware to change C2 infrastructure or facilitate lateral movement.

## Attack Chain

1.  **Initial Access:** Threat actors employ social engineering to lure victims into clicking a malicious link on a webpage or opening a crafted `.application` file, initiating a ClickOnce deployment.
2.  **Initial Execution:** The ClickOnce deployment process downloads and executes an application, which may initially appear benign. This execution leverages legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`.
3.  **Persistence Establishment:** During or after the initial deployment, the ClickOnce application drops an `.appref-ms` shortcut in the user's Start Menu. Adversaries exploit this by placing the `.appref-ms` file directly into the Windows Startup folder or configuring a scheduled task to ensure automatic re-execution.
4.  **Defense Evasion & Stealth:** The malicious payload executes within the context of trusted Microsoft system processes (`rundll32.exe`, `dfsvc.exe`), making it harder to detect compared to direct malware execution and allowing it to bypass common security monitoring and traditional `.exe` file scrutiny.
5.  **Malicious Update Push:** The attacker, either by compromising a legitimate ClickOnce deployment server or controlling their own, pushes a malicious update to the already deployed application.
6.  **Re-Execution & Malicious Payload Delivery:** Upon the next launch of the `.appref-ms` shortcut (either manually by the user or automatically via persistence mechanisms), the ClickOnce client automatically fetches and executes the malicious update without requiring additional user authorization.
7.  **Impact & Post-Exploitation:** The updated malware gains persistent remote access, establishes command and control (C2), facilitates further malware delivery, enables lateral movement, and conducts other post-exploitation activities like data exfiltration or system compromise.

## Impact

While no specific victim counts are detailed in this report, the abuse of ClickOnce technology allows threat actors to successfully bypass traditional endpoint security, achieve persistence, and maintain long-term access to compromised systems. The lack of administrative privileges required for installation enables widespread targeting of any user account within an enterprise. If successful, attackers can leverage the built-in update mechanism to continuously evolve their malware, change C2 infrastructure, and perform lateral movement, leading to significant data breaches, ransomware deployment, or other disruptive activities without triggering common alerts. The stealthy execution within legitimate processes further prolongs dwell time and complicates incident response efforts.

## Recommendation

*   Deploy the "Detect ClickOnce .appref-ms File Persistence in Startup Folder" Sigma rule to detect persistence mechanisms leveraged by threat actors.
*   Implement user awareness training to educate employees about the risks associated with clicking suspicious links and opening unfamiliar `.application` files, as highlighted by the initial access techniques.
*   Review and monitor for the creation or modification of `.appref-ms` files, especially in unusual directories outside of standard user Start Menu paths, as described in the attack chain.
*   Ensure Sysmon FileCreate event logging is enabled to capture `.appref-ms` file creation events, necessary for the recommended Sigma rule.
