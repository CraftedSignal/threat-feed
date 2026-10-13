---
title: Insecure Download Vulnerability in Powerlevel10k gitstatus Component
slug: 2026-10-powerlevel10k-insecure-download
description: Powerlevel10k versions through 1.20.0 execute malicious code via an insecure gitstatus installation script that disables TLS certificate verification and lacks integrity checks.
date: "2026-10-13T18:37:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:powerlevel10k_project:powerlevel10k:*:*:*:*:*:*:*:*
tags:
  - insecure-download
  - code-execution
  - shell-security
  - supply-chain
vendors:
  - Powerlevel10k
products:
  - Powerlevel10k (<= 1.20.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The script allows a network-positioned attacker to substitute a malicious archive during the installation process.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The malicious archive runs as the gitstatusd daemon under the user's account on every prompt.
    confidence_band: high
cves:
  - id: CVE-2026-110102
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110102
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Endpoint Security
  immediate_actions:
    - action: Upgrade Powerlevel10k to version > 1.20.0
      owner: IT Operations
      due: 48h
      evidence: Source CVE-2026-110102 indicates versions <= 1.20.0 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Verify installation of sha256sum on all managed endpoints
      owner: IT Operations
      addresses: CVE-2026-110102
      evidence: Script falls back to insecure mode if sha256sum is missing
---

Powerlevel10k, a popular theme for the Zsh shell, contains a critical vulnerability in its `gitstatus/install` script affecting versions up to 1.20.0. The installation process for the `gitstatus` component utilizes `curl -k` to download binaries, effectively disabling TLS certificate validation. Furthermore, the script skips essential integrity checks if the `sha256sum` utility is not present on the system. These design flaws allow a network-positioned attacker to perform a man-in-the-middle (MitM) attack, intercepting the request to the download mirror and substituting a malicious archive. Once the script completes, the malicious binary is executed as the `gitstatusd` daemon with the privileges of the user who initiated the shell session. Given that `gitstatusd` is invoked on every shell prompt, this results in persistent, unauthorized code execution within the user's environment.

## Attack Chain

1. Attacker establishes a network-positioned vantage point between the victim and the download mirror.
2. Victim executes a command triggering the `gitstatus/install` script, such as initializing or updating the shell theme.
3. Attacker intercepts the HTTPS request initiated by the insecure `curl -k` command.
4. Attacker returns a malicious binary archive instead of the legitimate `gitstatusd` component.
5. The script extracts the malicious binary to the local filesystem without performing integrity validation.
6. The shell theme executes the malicious file, establishing it as the persistent `gitstatusd` daemon.
7. Every time the victim opens a terminal or executes a command, `gitstatusd` runs malicious code under the user's account.

## Impact

Successful exploitation results in arbitrary code execution under the privileges of the victim's user account. This impact is persistent across terminal sessions, potentially leading to full account compromise, credential theft, and lateral movement within the environment. This vulnerability affects any environment utilizing Powerlevel10k versions 1.20.0 or older, including developer workstations and server environments configured with this theme.

## Recommendation

1. Upgrade Powerlevel10k to a version beyond 1.20.0 immediately.
2. Audit user home directories for the existence of `gitstatusd` binaries that do not match known cryptographic hashes.
3. Ensure that `sha256sum` or equivalent integrity verification utilities are installed and functional on all systems to prevent fallback to insecure installation modes.
4. Restrict outgoing network connections from servers and workstations to prevent unauthorized communication with unknown download mirrors.
