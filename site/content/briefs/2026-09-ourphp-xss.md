---
title: Reflected XSS in Ourphp via ourphp_out.php
slug: 2026-09-ourphp-xss
description: Ourphp versions 7.2.0 and earlier are vulnerable to reflected cross-site scripting (XSS) via the 'out' parameter in the 'ourphp_out.php' endpoint, allowing unauthorized script execution in a victim's browser session.
date: "2026-09-18T10:28:02Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:ourphp:ourphp:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - cve-2023-30212
vendors:
  - Ourphp
products:
  - Ourphp (<= 7.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The vulnerability allows an attacker to inject arbitrary script code which executes in the context of the user's browser.
    confidence_band: high
cves:
  - id: CVE-2023-30212
    cvss: 6.1
    epss: 0.08115
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ARUNSNAP-CVE-2023-30212-POC
rules:
  - title: Detect CVE-2023-30212 Exploitation Attempt
    description: Detects exploitation attempts against CVE-2023-30212 by looking for script tags in the 'out' parameter of the ourphp_out.php endpoint
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all web servers to identify Ourphp 7.2.0 and earlier instances
      owner: SOC
      due: 24h
      evidence: Source confirms Ourphp <= 7.2.0 is vulnerable
  hunt_leads:
    - lead: Search web logs for requests to /client/manage/ourphp_out.php containing URL-encoded script tags
      technique_id: T1059.007
      data_needed:
        - Web access logs (cs-uri-query)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC demonstrates XSS injection via this parameter
  mitigation_plan:
    - priority: short_term
      action: Implement a Web Application Firewall (WAF) rule to block requests to /client/manage/ourphp_out.php containing script metacharacters
      owner: Network Security
      addresses: CVE-2023-30212
      evidence: Mitigation of XSS vulnerability
---

Ourphp versions 7.2.0 and earlier contain a reflected cross-site scripting (XSS) vulnerability, identified as CVE-2023-30212. The vulnerability resides in the '/client/manage/ourphp_out.php' file, where the 'out' parameter is insufficiently sanitized when the 'ourphp_admin' parameter is set to 'logout'. An attacker can craft a malicious URL containing arbitrary JavaScript payloads, which will then be executed within the context of a victim's browser if they navigate to the link. This flaw, classified with a CVSS 6.1 score, poses a risk of session hijacking, credential theft, and unauthorized actions performed on behalf of the victim. Public proof-of-concept (PoC) code has been released, increasing the risk of exploitation for organizations still running affected versions of the software.

## Attack Chain

1. Attacker identifies a target running Ourphp version 7.2.0 or earlier.
2. Attacker crafts a malicious URL pointing to the vulnerable endpoint: '/client/manage/ourphp_out.php?ourphp_admin=logout&out=[PAYLOAD]'.
3. Attacker injects a JavaScript payload into the 'out' parameter (e.g., '&lt;script>alert(1)&lt;/script>').
4. Attacker uses social engineering or phishing to trick an authenticated or targeted user into clicking the malicious link.
5. The victim's browser requests the endpoint with the injected script.
6. The Ourphp application reflects the unsanitized payload back to the victim's browser.
7. The browser executes the injected script in the context of the user's active session, enabling token theft or forced actions.

## Impact

Successful exploitation of CVE-2023-30212 enables an attacker to execute arbitrary scripts in the victim's browser session. This can lead to the compromise of user sessions, theft of sensitive information (such as session cookies or CSRF tokens), and the potential to perform unauthorized administrative actions if the victim is an authorized user. The vulnerability is network-accessible and requires user interaction, making it a viable target for credential-harvesting or session-hijacking campaigns.

## Recommendation

* Prioritize upgrading all instances of Ourphp to a version beyond 7.2.0, as there is currently no evidence of an official patch release for this specific legacy version mentioned in the source material.
* Deploy the Sigma rule below to monitor for exploitation attempts targeting the identified endpoint in web server logs.
* Implement Content Security Policy (CSP) headers to mitigate the impact of reflected XSS by restricting where scripts can be loaded and executed.
* Educate users on the risks of clicking suspicious links, especially those directing to internal administrative portals.
