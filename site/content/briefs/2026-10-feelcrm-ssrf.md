---
title: SSRF Vulnerability in feelcrm-os via GoogleController
slug: 2026-10-feelcrm-ssrf
description: An unauthenticated server-side request forgery (SSRF) vulnerability in feelcrm-os 1.0.0 allows remote attackers to force the server to perform unauthorized HTTP requests by manipulating the url parameter.
date: "2026-10-05T11:39:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:feelec_yishu:feelcrm_os:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
vendors:
  - feelec-yishu
products:
  - feelcrm-os (1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument url can lead to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-105290
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105290
rules:
  - title: Detect CVE-2026-105290 Exploitation - SSRF in feelcrm-os
    description: Detects exploitation of CVE-2026-105290 by identifying suspicious URL arguments in requests to the GoogleController endpoint that target private address spaces.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy webserver detection rule to monitor for internal IP requests
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-105290 SSRF vulnerability
  hunt_leads:
    - lead: Logs showing hits to GoogleController.class.php with URL parameters containing internal IP addresses
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows manipulation of the url argument to trigger SSRF.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound egress from the web server hosting feelcrm-os
      owner: IT Operations
      addresses: CVE-2026-105290
      evidence: SSRF vulnerability allows access to internal network
---

CVE-2026-105290 identifies a critical server-side request forgery (SSRF) vulnerability within feelcrm-os version 1.0.0. The vulnerability resides in the getCurlData endpoint, specifically within the file App/Feelcrm/Index/Controller/GoogleController.class.php. An attacker can supply a malicious URL through the 'url' argument, which the application then requests on behalf of the server. This allows remote, unauthenticated attackers to interact with internal network resources or external services, potentially leading to unauthorized data exfiltration or access to internal administration interfaces. Public disclosure of the vulnerability has occurred, and as of the publication date, the project maintainers have not released a patch or responded to initial vulnerability reports.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass perimeter security to scan and interact with internal network services that are otherwise inaccessible from the public internet. This can lead to unauthorized access to cloud metadata services, internal API endpoints, or private management interfaces, potentially resulting in complete compromise of the underlying server if secondary vulnerabilities are identified within the internal network.

## Recommendation

1. Restrict outbound network access from the host running feelcrm-os to only essential external services, effectively neutralizing the impact of potential SSRF exploitation.
2. Implement strict input validation on the 'url' parameter for the GoogleController endpoint to permit only expected domain patterns.
3. Monitor web access logs for anomalous requests to the '/App/Feelcrm/Index/Controller/GoogleController.class.php' path, particularly those containing suspicious URL parameters or attempts to access internal IP addresses (e.g., 127.0.0.1, 169.254.169.254).
4. Monitor for potential exploitation attempts targeting this specific file until an official vendor patch is released.
