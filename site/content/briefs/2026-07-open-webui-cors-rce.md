---
title: CVE-2026-56400 open-webui Cross-Origin Resource Sharing Misconfiguration Leads to RCE
slug: 2026-07-open-webui-cors-rce
description: A cross-origin resource sharing (CORS) misconfiguration in open-webui versions prior to 0.3.14 allows remote attackers to achieve arbitrary code execution by crafting malicious cross-site requests that an authenticated administrator user visits.
date: "2026-07-15T12:23:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - vulnerability
  - web-exploitation
  - cors
  - rce
vendors:
  - open-webui
products:
  - open-webui
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: open-webui before 0.3.14 contains a cross-origin resource sharing misconfiguration allowing arbitrary origins with allow_origins=* and authenticated requests to the /api/v1/functions endpoint. Attackers can execute arbitrary code on the openwebui instance
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: crafting malicious cross-site requests from attacker-controlled websites when an admin user visits them.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can execute arbitrary code on the openwebui instance
    confidence_band: high
cves:
  - id: CVE-2026-56400
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56400
  - https://github.com/open-webui/open-webui/security/advisories/GHSA-6xcp-7mpr-m7wm
  - https://www.vulncheck.com/advisories/open-webui-remote-code-execution-via-cors-misconfiguration-and-session-validation
---

CVE-2026-56400 describes a critical vulnerability in open-webui versions prior to 0.3.14, stemming from a cross-origin resource sharing (CORS) misconfiguration. The application's `allow_origins=*` setting, coupled with authenticated access to the `/api/v1/functions` endpoint, creates a pathway for remote code execution (RCE). Attackers can exploit this by hosting a malicious website containing specially crafted JavaScript. If an authenticated administrator user of an affected open-webui instance visits this attacker-controlled site, the malicious script can bypass same-origin policy restrictions and make authenticated requests to the vulnerable `/api/v1/functions` endpoint on the open-webui server, leading to arbitrary code execution. This vulnerability poses a significant risk as it allows an unauthenticated attacker to compromise the entire open-webui instance if an admin user is successfully enticed to a malicious page.

## Attack Chain

1. **Attacker hosts a malicious website:** The attacker prepares a website containing JavaScript code designed to exploit the CORS misconfiguration in open-webui.
2. **Attacker lures an authenticated open-webui admin user:** The attacker uses social engineering or other means to trick an administrator user of an open-webui instance into visiting the malicious website.
3. **Malicious JavaScript executes in the victim's browser:** Upon visiting the attacker's site, the malicious JavaScript payload is executed within the context of the administrator's web browser.
4. **Cross-origin authenticated request initiated:** The malicious JavaScript crafts and sends an authenticated `POST` request to the vulnerable `[open-webui-host]/api/v1/functions` endpoint, leveraging the victim's active session cookies.
5. **CORS misconfiguration bypasses security:** Due to the `allow_origins=*` setting on the open-webui server, the cross-origin request is allowed by the server and processed as if it originated from the legitimate open-webui domain, accepting the victim's authentication.
6. **Remote code execution via `/api/v1/functions`:** The specific vulnerability within the `/api/v1/functions` endpoint is triggered by parameters within the crafted request, leading to arbitrary code execution on the underlying open-webui server.
7. **Attacker achieves objectives:** With arbitrary code execution, the attacker can achieve various objectives, such as installing backdoors, exfiltrating data, or further compromising the system.

## Impact

Successful exploitation of CVE-2026-56400 grants an attacker arbitrary code execution on the open-webui instance. This can lead to complete compromise of the open-webui application and potentially the underlying server, allowing for data exfiltration, unauthorized access, deployment of further malicious payloads, or denial of service. The impact extends to any data or services managed by the open-webui instance, posing a significant risk to the integrity and confidentiality of information processed by the system.

## Recommendation

* Upgrade open-webui instances to version 0.3.14 or later immediately to patch CVE-2026-56400.
* Educate users, particularly administrators, about the risks of visiting untrusted websites and the importance of recognizing phishing attempts, which are part of the attack chain for CVE-2026-56400.
* Monitor webserver logs for unexpected `POST` requests to the `/api/v1/functions` endpoint originating from unusual `Referer` or `Origin` headers (if your webserver logs capture these).
