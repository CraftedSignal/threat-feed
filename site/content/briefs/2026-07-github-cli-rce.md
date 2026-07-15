---
title: GitHub CLI `gh codespace jupyter` Command Remote Code Execution Vulnerability
slug: 2026-07-github-cli-rce
description: A remote code execution vulnerability, CVE-2026-59831, has been identified in the GitHub CLI's `gh codespace jupyter` command, allowing attackers to execute arbitrary code on a user's system when connecting to a specially crafted malicious Codespace.
date: "2026-07-15T07:45:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - remote-code-execution
  - vulnerability
  - github
  - cli
  - codespaces
  - developer-tools
vendors:
  - GitHub
products:
  - GitHub CLI
  - GitHub Codespaces
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This flaw allows attackers to execute arbitrary code on a user's system if the user connects to a specially crafted malicious Codespace.
    confidence_band: high
cves:
  - id: CVE-2026-59831
    cvss: 4.4
    epss: 0.00198
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59831
---

A critical remote code execution vulnerability, identified as CVE-2026-59831, exists within the GitHub CLI's `gh codespace jupyter` command. This flaw allows an attacker to achieve arbitrary code execution on a user's system if the user connects to a specifically crafted malicious Codespace. The vulnerability targets the GitHub CLI, affecting Windows, Linux, and macOS platforms. Attackers can leverage this by creating a malicious Codespace environment designed to execute code when a victim initializes a Jupyter environment using the vulnerable command. The primary impact is the compromise of the user's local machine, potentially leading to further system compromise, data exfiltration, or persistence. This highlights the risk associated with untrusted development environments and the importance of timely updates for developer tools.

## Attack Chain

1. An attacker creates a malicious GitHub Codespace, embedding code designed for arbitrary execution within its configuration or initial environment setup.
2. The attacker lures a target developer to connect to this malicious Codespace, potentially via social engineering or compromising a legitimate repository.
3. The victim developer executes the `gh codespace jupyter` command on their local machine, intending to set up a Jupyter environment for the Codespace.
4. During the connection and initialization process, the GitHub CLI interacts with the malicious Codespace.
5. Due to CVE-2026-59831, the GitHub CLI's `gh codespace jupyter` command improperly handles content or configurations received from the malicious Codespace.
6. The embedded malicious code from the Codespace is executed on the victim's local machine with the privileges of the user running the `gh codespace jupyter` command.
7. The attacker gains remote code execution on the victim's system, allowing for actions such as installing malware, exfiltrating credentials, or establishing persistence.

## Impact

Successful exploitation of CVE-2026-59831 leads to arbitrary remote code execution on the victim's local machine. This compromise allows attackers to take control of the affected system, potentially installing additional malware, exfiltrating sensitive data, modifying system configurations, or establishing long-term persistence within the victim's environment. Given the nature of developer tools, a compromised developer workstation could provide attackers with access to source code repositories, internal networks, or cloud environments, leading to significant intellectual property theft or broader organizational compromise. All users of GitHub CLI across Windows, Linux, and macOS platforms who interact with GitHub Codespaces are at risk if they connect to untrusted environments.

## Recommendation

* Patch CVE-2026-59831 immediately by updating the GitHub CLI to a non-vulnerable version.
* Educate users about the risks of connecting to untrusted or suspicious GitHub Codespaces.
* Review and implement secure development environment practices, including validation of Codespace origins.
