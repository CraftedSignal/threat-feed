---
title: Jupyter Server Stored XSS via Missing CSP Sandbox (CVE-2026-44727)
slug: 2026-06-jupyter-server-xss
description: A critical stored Cross-Site Scripting (XSS) vulnerability, CVE-2026-44727, exists in `jupyter_server` versions up to 2.19.0 due to a missing `sandbox` directive in Content-Security-Policy (CSP) headers, allowing authenticated attackers to craft malicious notebooks that exfiltrate victim tokens and achieve kernel Remote Code Execution (RCE) when viewed.
date: "2026-06-18T15:20:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - web-vulnerability
  - jupyter
  - server-side
  - rce
vendors:
  - Jupyter
products:
  - jupyter_server (<= 2.19.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1559
    technique_name: Adversary-in-the-Middle
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-fcw5-x6j4-ccmp
rules:
  - title: Detects CVE-2026-44727 Exploitation — Jupyter `nbconvert` HTML Handler Access
    description: Detects HTTP GET requests to the `/nbconvert/html/` endpoint in `jupyter_server`, indicating access to a component vulnerable to stored XSS via CVE-2026-44727. This helps identify instances where user-authored notebooks are being rendered, potentially triggering a malicious payload.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-44727 Probing — Suspicious Characters in Jupyter `nbconvert` Path
    description: Detects HTTP requests to the `/nbconvert/html/` endpoint in `jupyter_server` containing characters commonly associated with path traversal or command injection attempts within the URI stem. While CVE-2026-44727 is a stored XSS, such patterns can indicate probing for other vulnerabilities or unexpected exploitation attempts against the nbconvert handlers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - reconnaissance
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
rules_count: 2
---

Jupyter Server, versions up to 2.19.0, is affected by a critical stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-44727. This flaw resides in the `NbconvertFileHandler` and `NbconvertPostHandler` components, specifically due to a missing `sandbox` directive in their Content-Security-Policy (CSP). This oversight allows user-authored Jupyter notebooks containing malicious HTML payloads within `display_data` output to be rendered without proper sanitization or isolation. An authenticated attacker can craft such a notebook and share it. When an unsuspecting, authenticated victim navigates to the malicious notebook's output via the `/nbconvert/html/<path>` endpoint, the embedded script executes within their browser under the Jupyter origin. This grants the attacker potential access to the victim's authentication tokens, leading to cookie exfiltration, and can be escalated to full `/api/*` authority and kernel Remote Code Execution (RCE) on the server. This vulnerability poses a significant risk to the integrity and confidentiality of data on affected Jupyter environments.

## Attack Chain

1.  **Attacker Crafts Malicious Jupyter Notebook**: An authenticated attacker creates a Jupyter notebook containing a specially crafted HTML payload within a `display_data` output cell, embedding malicious JavaScript.
2.  **Attacker Uploads/Shares Notebook**: The attacker uploads this malicious notebook to a vulnerable `jupyter_server` instance (versions up to 2.19.0) or shares it with potential victims.
3.  **Victim Accesses Server**: An authenticated victim logs into the `jupyter_server` instance.
4.  **Triggering XSS**: The victim navigates their browser to the malicious notebook's output view, which is rendered via the `/nbconvert/html/<path>` endpoint handled by `NbconvertFileHandler` or `NbconvertPostHandler`.
5.  **Vulnerable Rendering**: The `jupyter_server` renders the user-authored HTML content. Due to the missing `sandbox` directive in the Content-Security-Policy, the malicious HTML is not isolated and executes without restrictions.
6.  **Client-Side Execution**: The embedded malicious JavaScript executes within the victim's browser, operating under the same origin as the `jupyter_server`.
7.  **Token Exfiltration**: The executing script accesses the victim's authentication tokens (e.g., cookies, session tokens) and exfiltrates them to an attacker-controlled domain.
8.  **Kernel RCE**: Leveraging the victim's authenticated session, the script utilizes full `/api/*` authority to interact with Jupyter's internal APIs, potentially achieving Remote Code Execution on the Jupyter kernel or the underlying server.

## Impact

The successful exploitation of CVE-2026-44727 can lead to severe consequences for affected `jupyter_server` instances. An authenticated victim's session tokens, including cookies, can be exfiltrated to an attacker-controlled domain, compromising user accounts and sensitive data. Furthermore, the malicious script executing with full `/api/*` authority can be used to interact with the Jupyter environment, potentially achieving kernel Remote Code Execution (RCE). This allows an attacker to execute arbitrary commands on the server hosting the Jupyter kernel, leading to data theft, system compromise, or further network penetration. The vulnerability impacts any organization or individual using `jupyter_server` for data analysis, development, or educational purposes, especially in collaborative environments where users might share notebooks.

## Recommendation

*   Immediately patch `jupyter_server` to version v2.20.0 or higher to address CVE-2026-44727.
*   For deployments where patching is impractical, implement the provided workaround by adding the Content-Security-Policy modification to your `jupyter_server_config.py` file.
*   Deploy the Sigma rules "Detects CVE-2026-44727 Exploitation — Jupyter `nbconvert` HTML Handler Access" and "Detects CVE-2026-44727 Probing — Suspicious Characters in Jupyter `nbconvert` Path" to your SIEM for monitoring.
*   Ensure `webserver` logs are collected and ingested into your security monitoring platform to enable detection of these activities.
