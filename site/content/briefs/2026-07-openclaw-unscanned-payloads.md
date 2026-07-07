---
title: OpenClaw Vulnerability Allows Loading of Unscanned Payloads via Malicious Metadata
slug: 2026-07-openclaw-unscanned-payloads
description: A high-severity vulnerability, CVE-2026-53810, in OpenClaw's marketplace runtime extension metadata allows an attacker to craft a malicious package that, when installed by a trusted operator, redirects runtime loading to hidden, unscanned code, potentially leading to unauthorized code execution and bypassing security checks.
date: "2026-07-03T12:18:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - supply-chain
  - code-execution
  - nodejs
  - npm
vendors:
  - OpenClaw
products:
  - npm/openclaw (< 2026.5.18)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: this could load plugin code outside the reviewed package entry points
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: runtime loading toward hidden package content that was not scanned as expected
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: could load plugin code outside the reviewed package entry points... within OpenClaw's trusted-operator model
    confidence_band: med
cves:
  - id: CVE-2026-53810
    cvss: 8.8
    epss: 0.00419
references:
  - https://github.com/advisories/GHSA-v6r2-jh58-xx6w
---

A critical vulnerability, CVE-2026-53810, has been identified in `npm/openclaw` versions prior to `2026.5.18`. This flaw resides within the marketplace runtime extension metadata, allowing a malicious package to point to unscanned payloads. When a trusted operator installs such a specially crafted package, the OpenClaw Gateway's runtime loading mechanism can be redirected to execute hidden content that has bypassed expected security scans. This means plugin code could be loaded and executed outside of its reviewed package entry points, creating an avenue for unauthorized code execution. The practical impact hinges on the specific operator's configuration and whether lower-trust input can reach the vulnerable path. While this advisory emphasizes that OpenClaw's trusted-operator model remains, this specific misconfiguration introduces a significant risk if exploited.

## Attack Chain

1.  An attacker crafts a malicious OpenClaw package containing legitimate-looking components alongside hidden malicious code and specially forged marketplace runtime extension metadata.
2.  The attacker delivers this malicious package (e.g., via social engineering, compromise of a trusted source, or supply chain infiltration) to an organization using OpenClaw Gateway.
3.  A trusted operator, unaware of the hidden malicious content, initiates the installation of the seemingly benign package within the OpenClaw Gateway environment.
4.  During the installation process, the vulnerable OpenClaw Gateway (versions prior to `2026.5.18`) processes the malicious marketplace runtime extension metadata.
5.  Due to CVE-2026-53810, this metadata redirects the runtime loading mechanism to the hidden, unscanned malicious code within the package.
6.  The OpenClaw Gateway inadvertently loads and executes the malicious plugin code, bypassing its standard security review and scanning procedures.
7.  The executed malicious code operates within the trusted context of the OpenClaw Gateway, potentially allowing for arbitrary command execution, data exfiltration, or further system compromise.

## Impact

Successful exploitation of CVE-2026-53810 could lead to unauthorized code execution within the trusted environment of an OpenClaw Gateway. If the affected feature is enabled and reachable, attackers could leverage this vulnerability to bypass security scans and load arbitrary plugin code, potentially leading to privilege escalation, data theft, or complete system compromise. The severity of the impact depends heavily on the specific configuration of the operator's OpenClaw environment and the sensitivity of the data and systems accessible by the Gateway.

## Recommendation

*   Patch CVE-2026-53810 by immediately upgrading `npm/openclaw` to version `2026.5.18` or higher to remediate the vulnerability.
*   As a temporary mitigation, implement strict allowlists for all plugins installed on OpenClaw Gateways and explicitly define allowed channels and tools.
*   Disable the marketplace runtime extension feature if it is not explicitly required for your operational needs to reduce the attack surface.
*   Avoid sharing a single OpenClaw Gateway between mutually untrusted users or environments as a general hardening measure.
