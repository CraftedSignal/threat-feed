---
title: Unauthenticated SSRF in Openpanel Site Checker
slug: 2026-09-openpanel-ssrf
description: Openpanel versions before 2.3.0 are vulnerable to an unauthenticated server-side request forgery (SSRF) flaw in the /tools/site-checker endpoint that allows internal network probing and cloud metadata access.
date: "2026-09-04T13:26:07Z"
lastmod: "2026-09-04T13:26:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openpanel:openpanel:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
  - reconnaissance
  - remote-code-execution
  - injection
  - openpanel
vendors:
  - Openpanel
products:
  - Openpanel (< 2.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can access cloud instance metadata endpoints and probe internal services.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The endpoint ... performs server-side HTTP requests to arbitrary URLs without any SSRF/IP validation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Attackers can use the recovered constructor to load Node.js built-ins and execute operating system commands with the privileges of the API process.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: OpenPanel before 2.3.0 contains a cross-site scripting vulnerability in the unauthenticated favicon proxy endpoint GET /misc/favicon that allows remote attackers to execute scripts by supplying an SVG file URL.
    confidence_band: high
cves:
  - id: CVE-2026-85609
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85609
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85610
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85613
rules:
  - title: Detect CVE-2026-85609 Exploitation Attempt - SSRF via Site Checker
    description: Detects exploitation attempts against the Openpanel /tools/site-checker endpoint by identifying suspicious internal IP addresses or metadata service addresses in the URL query parameter.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all Openpanel installations to version 2.3.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Source document identifies version 2.3.0 as the remediation patch.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Openpanel to version 2.3.0.
      owner: IT Operations
      addresses: CVE-2026-85609
      evidence: NVD states Openpanel before 2.3.0 is vulnerable.
updates:
  - at: "2026-09-04T13:26:16Z"
    level: L2
    summary: added coverage for OpenPanel (< 2.3.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85610
  - at: "2026-09-04T13:26:29Z"
    level: L2
    summary: added coverage for OpenPanel (< 2.3.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85613
---

Openpanel versions prior to 2.3.0 contain a critical server-side request forgery (SSRF) vulnerability identified as CVE-2026-85609. The flaw exists in the GET /tools/site-checker endpoint, located in apps/api/src/controllers/tools.controller.ts, which fails to validate user-supplied URL inputs. An unauthenticated attacker can exploit this endpoint by providing a malicious URL parameter to the fetchWithRedirects function. 

This vulnerability allows attackers to perform unauthorized HTTP requests from the server context, enabling them to probe internal services, scan local network ports, and access cloud instance metadata services (such as AWS/GCP/Azure metadata endpoints). Furthermore, the application returns response details, including status codes, page sizes, and HTML metadata, which can be leveraged for network reconnaissance. The vulnerability also supports leaking internal IP address information to third-party endpoints via the getIPInfo function. Defenders should prioritize patching all Openpanel instances to version 2.3.0 or later to remediate this vector.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain unauthorized visibility into internal network infrastructure, potentially leading to information disclosure of sensitive internal configurations, cloud environment secrets, or local service status. This exposure could serve as a precursor to further exploitation of internal services that were not intended to be internet-facing.

## Recommendation

Prioritize the following actions to secure vulnerable Openpanel installations:

* Immediately upgrade all Openpanel instances to version 2.3.0 or later to address CVE-2026-85609.
* Implement egress filtering on the server hosting Openpanel to restrict network requests to authorized external domains only, preventing access to internal network segments or cloud metadata services.
* Audit web server access logs for repeated requests to /tools/site-checker containing suspicious query parameters, such as internal IP addresses (169.254.169.254, 10.x.x.x, 172.16-31.x.x, 192.168.x.x) or common internal service ports.
