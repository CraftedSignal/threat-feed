---
title: Stored XSS Vulnerability in OpenClaw Dashboard
slug: 2026-07-openclaw-xss
description: An unauthenticated stored XSS vulnerability in the OpenClaw Dashboard allows remote attackers to execute arbitrary JavaScript in administrative sessions via the sessions API.
date: "2026-07-30T23:32:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-application-security
  - xss
  - cve-2026-66421
vendors:
  - OpenClaw
products:
  - OpenClaw Dashboard
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: OpenClaw Dashboard contains a stored cross-site scripting vulnerability that allows unauthenticated remote attackers to execute arbitrary JavaScript in the administrator's browser session.
    confidence_band: high
cves:
  - id: CVE-2026-66421
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66421
---

OpenClaw Dashboard contains a stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-66421, which allows unauthenticated remote attackers to execute arbitrary JavaScript within the context of an administrator's browser session. The vulnerability originates in the sessions API, where user-supplied agent transcript messages are stored without proper sanitization. 

Attackers exploit this by injecting HTML markup containing event handler payloads, such as an `<img>` tag with an `onerror` attribute, into the transcript messages. These payloads are subsequently rendered by the OpenClaw Dashboard's default landing page through the use of `innerHTML`. The injection allows for the theft of administrative session tokens and the execution of unauthorized actions, including the modification of agent instruction files. Given the impact on administrative session integrity and authorization controls, this vulnerability poses a critical risk to organizations relying on OpenClaw Dashboard for infrastructure management.

## Impact

Successful exploitation allows for complete compromise of an administrator's session. Potential consequences include the theft of sensitive session identifiers, unauthorized access to administrative dashboard functions, and the ability to modify critical agent instruction files, which could lead to further downstream system compromise or data exfiltration.

## Recommendation

* Prioritize patching OpenClaw Dashboard to the latest version provided by the vendor to remediate CVE-2026-66421.
* Audit web server logs for HTTP requests to the sessions API that contain suspicious HTML tags or event handlers, such as `onerror`, `onload`, or `script`.
* Restrict access to the OpenClaw Dashboard administrative interface to trusted management networks to minimize the exposure to unauthenticated external actors.
