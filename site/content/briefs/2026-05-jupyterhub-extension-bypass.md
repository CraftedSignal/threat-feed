---
title: JupyterHub Extension Manager API/GUI Policy Discrepancy Allows Malicious Extension Installation
slug: 2026-05-jupyterhub-extension-bypass
description: JupyterLab versions prior to 4.5.7 do not correctly enforce the allow-list of extensions that can be installed from PyPI Extension Manager, allowing authenticated attackers to escalate privileges and potentially exfiltrate data, move laterally, and persistently compromise server infrastructure.
date: "2026-05-05T20:53:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - jupyterhub
  - jupyterlab
  - privilege-escalation
  - vulnerability
  - extension-manager
vendors:
  - Jupyter
  - pip
products:
  - JupyterHub
  - JupyterLab (< 4.5.7)
  - Notebook
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-37w4-hwhx-4rc4
  - https://jupyterlab.readthedocs.io/en/stable/user/extensions.html#listing-configuration
  - https://jupyterhub.readthedocs.io/en/5.2.1/explanation/websecurity.html
  - https://jupyterlab.readthedocs.io/en/latest/user/extensions.html#extension-manager-implementations
rules:
  - title: Detect JupyterLab Extension Installation Attempt
    description: Detects attempts to install JupyterLab extensions via POST requests, which could indicate exploitation of the extension manager vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect JupyterLab Read-Only Extension Manager Configuration
    description: Detects when JupyterLab is configured with a read-only extension manager, which is a suggested workaround for the extension installation vulnerability.
    platform: sigma
    severity: informational
    techniques:
      - T1546.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

JupyterLab versions prior to 4.5.7 contain a vulnerability in the handling of the allow-list (`allowed_extensions_uris`) for extensions installable via the PyPI Extension Manager. This vulnerability allows an authenticated attacker to bypass the intended restrictions on extension installation, even in environments where such installations should be limited or prevented. This is particularly concerning for JupyterHub deployments aiming to restrict user capabilities for security reasons.  The vulnerability exists because the PyPI Extension Manager was not properly restricted to packages listed on the default PyPI index. This can lead to privilege escalation within the JupyterHub environment.

## Attack Chain

1.  Attacker authenticates to a JupyterHub instance with a standard user account.
2.  Attacker identifies that the JupyterHub instance has the PyPI Extension Manager enabled.
3.  Attacker discovers that the `allowed_extensions_uris` list is not correctly enforced in the JupyterLab version running on the server (versions < 4.5.7).
4.  Attacker crafts a POST request to install a malicious extension from a non-allow-listed PyPI index or a local package.
5.  JupyterLab incorrectly processes the request, bypassing the intended allow-list restrictions.
6.  The malicious extension is installed into the JupyterLab environment.
7.  The extension executes malicious code, potentially escalating the attacker's privileges.
8.  Attacker gains access to sensitive data, moves laterally to other systems, or establishes persistence on the server.

## Impact

Successful exploitation allows an authenticated attacker to escalate privileges within the JupyterHub environment. This may lead to data exfiltration from the JupyterHub server or connected systems. Lateral movement to other systems on the network becomes possible, potentially compromising other services. A persistent compromise of the server infrastructure could also be achieved, allowing for long-term control and data access. This vulnerability impacts multi-tenant deployments and shared environments such as educational institutions where students share JupyterHub instances.

## Recommendation

*   Upgrade JupyterLab to version 4.5.7 or later to patch the vulnerability (JupyterLab v4.5.7).
*   As a temporary workaround, switch to the read-only extension manager by adding the command line option `--LabApp.extension_manager=readonly` or the traitlet `c.LabApp.extension_manager = 'readonly'` to your JupyterLab configuration.
*   Deploy the Sigma rule `Detect JupyterLab Extension Installation Attempt` to identify unauthorized extension installation attempts.
*   Monitor web server logs for POST requests to extension installation endpoints to identify potential exploit attempts (webserver logs).
