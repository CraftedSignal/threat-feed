---
title: DataGear Server-Side Request Forgery in /dataSet/preview/Http
slug: 2026-09-datagear-ssrf
description: DataGear versions up to 6.0.0 contain an unauthenticated server-side request forgery vulnerability allowing attackers to perform arbitrary internal HTTP requests and exfiltrate response bodies.
date: "2026-09-16T15:52:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:datagear:datagear:*:*:*:*:*:*:*:*
vendors:
  - DataGear
products:
  - DataGear (<= 6.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: DataGear through 6.0.0 contains a server-side request forgery vulnerability in the /dataSet/preview/Http endpoint that allows unauthenticated attackers to execute arbitrary HTTP requests.
    confidence_band: high
cves:
  - id: CVE-2026-92566
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92566
rules:
  - title: Detect CVE-2026-92566 Exploitation - SSRF Attempt via DataGear
    description: Detects exploitation attempts against CVE-2026-92566 by identifying requests to the vulnerable /dataSet/preview/Http endpoint that target internal or cloud metadata IP ranges.
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
    - action: Deploy detection rule to identify attempts to hit internal endpoints via the DataGear preview feature
      owner: Detection Engineering
      due: 24h
      evidence: NVD vulnerability disclosure for CVE-2026-92566
  mitigation_plan:
    - priority: immediate
      action: Restrict DataGear egress traffic and access to the management interface
      owner: IT Operations
      addresses: CVE-2026-92566
      evidence: SSRF vulnerability allows arbitrary requests
---

DataGear through version 6.0.0 contains a critical server-side request forgery (SSRF) vulnerability located within the /dataSet/preview/Http endpoint. This vulnerability allows an unauthenticated remote attacker to force the DataGear application to initiate unauthorized HTTP requests to arbitrary targets, including internal network infrastructure, internal services, and cloud environment metadata services. 

The application fails to validate the user-supplied URI parameter before executing the request, enabling support for various HTTP methods such as GET, POST, PUT, PATCH, and DELETE. Successful exploitation results in the disclosure of internal network configuration, service responses, and sensitive data that is otherwise unreachable from the public internet. Because the application returns the full response body of the requested resource to the attacker, this flaw presents a high risk for data exfiltration and internal reconnaissance. Defenders must prioritize restricting outbound network access from the DataGear server and ensuring the application is updated once a patch is available.
