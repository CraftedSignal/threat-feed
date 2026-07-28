---
title: Artica Proxy Session Fixation Vulnerability CVE-2026-66745
slug: 2026-07-artica-proxy-session-fixation
description: A session fixation vulnerability, CVE-2026-66745, in Artica Proxy before version 4.50.000000 Service Pack 7 allows unauthenticated attackers to hijack administrative sessions by pre-setting a PHPSESSID on a victim's browser, leading to full administrative control upon victim authentication.
date: "2026-07-28T19:27:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - session-fixation
  - web-application
  - proxy
vendors:
  - ArticaTech
products:
  - Artica Proxy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Artica Proxy before 4.50.000000 Service Pack 7 [...] contains a session fixation vulnerability that allows unauthenticated attackers to hijack administrative sessions
    confidence_band: high
cves:
  - id: CVE-2026-66745
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66745
  - https://wiki.articatech.com/maintenance/upgrade-artica/hotfix-450000000
  - https://www.articatech.com/hotfixes.php?main=4.50.000000&sp=7
  - https://www.vulncheck.com/advisories/artica-proxy-session-fixation-via-fw-login-php
iocs:
  - type: other
    value: PHPSESSID
ioc_counts:
  other: 1
---

CVE-2026-66745 is a critical session fixation vulnerability impacting Artica Proxy installations prior to version 4.50.000000 Service Pack 7, which was addressed in hotfix 20260724-02. This flaw enables unauthenticated attackers to gain full administrative access to an affected Artica Proxy instance without needing valid credentials. The attack involves the adversary setting a specific, known PHPSESSID cookie in a victim's browser before the victim authenticates. When the legitimate user subsequently logs into the Artica Proxy via the `fw.login.php` page, the vulnerable application reuses the attacker-controlled session identifier instead of creating a new, unique one. This allows the attacker to use the pre-set PHPSESSID to access the administrative interface, typically on port 9000, as a fully authenticated user. The vulnerability's ease of exploitation and potential for complete system compromise make it a significant concern for organizations using Artica Proxy.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable Artica Proxy instance exposed to the internet.
2. The attacker generates a specific, attacker-controlled PHPSESSID value.
3. The attacker crafts a malicious link or web page that, when visited by a target administrative user, sets the attacker-controlled PHPSESSID cookie for the Artica Proxy domain in the user's browser.
4. The legitimate administrative user is lured to the Artica Proxy login page, `fw.login.php`, with the pre-set PHPSESSID cookie already present.
5. The administrative user provides their valid credentials and successfully authenticates to the Artica Proxy.
6. Due to the session fixation vulnerability, the Artica Proxy server reuses the existing, attacker-controlled PHPSESSID for the newly authenticated session instead of issuing a fresh one.
7. The attacker then uses their browser, which still holds the pre-set PHPSESSID, to navigate directly to the Artica Proxy administrative interface, typically accessible on port 9000.
8. The Artica Proxy validates the attacker's PHPSESSID, granting the attacker a fully authenticated administrative session and complete control over the proxy server.

## Impact

Successful exploitation of CVE-2026-66745 grants an unauthenticated attacker full administrative privileges over the affected Artica Proxy instance. This allows for complete control over network traffic, including the ability to monitor, redirect, or block user activity, manipulate data, and potentially pivot to other systems within the internal network. The compromise of a proxy server can lead to significant data breaches, unauthorized access to internal resources, and disruption of critical network services, affecting all users whose traffic flows through the compromised proxy.

## Recommendation

* Immediately apply the hotfix 20260724-02 or upgrade Artica Proxy to version 4.50.000000 Service Pack 7 or later to patch CVE-2026-66745. Refer to the vendor's release notes linked in the references for instructions.
* Monitor web server logs for suspicious requests to `fw.login.php` that include unusual or repeated PHPSESSID values from different client IPs, which could indicate attempts to exploit this vulnerability.
* Implement secure cookie attributes (e.g., `HttpOnly`, `Secure`, `SameSite`) and consider session regeneration upon authentication to mitigate session fixation attacks.
