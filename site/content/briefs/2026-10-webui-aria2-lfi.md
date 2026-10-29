---
brief_id: brief-2026-10-29-webui-aria2-lfi
event_id: brief-2026-10-29-webui-aria2-lfi
revision: 1
activity_at: "2026-10-29T11:01:54Z"
title: 'Ziahamza webui-aria2: Local file inclusion (CVE-2023-39141)'
slug: 2026-10-webui-aria2-lfi
description: An unauthenticated local file inclusion vulnerability in Ziahamza webui-aria2 allows remote attackers to perform file enumeration, with publicly available proof-of-concept exploit code increasing the risk of information disclosure.
date: "2026-10-29T11:01:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Exploit behavior verified via public POC report; environmental validation pending.
cpes:
  - cpe:2.3:a:ziahamza:webui-aria2:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ziahamza:webui-aria2:-:*:*:*:*:*:*:*
tags:
  - lfi
  - vulnerability
  - webui-aria2
vendors:
  - Ziahamza
products:
  - webui-aria2 (All versions)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an unauthenticated remote attacker to perform file enumeration on the host system.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: LFI-enumerator tool exploits CVE-2023-39141 to enumerate remote server files.
    confidence_band: high
cves:
  - id: CVE-2023-39141
    cvss: 7.5
    epss: 0.03367
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MARTISABATE-CVE-2023-39141-LFI-ENUMERATOR
  - https://gist.github.com/JafarAkhondali/528fe6c548b78f454911fb866b23f66e
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MARTISABATE-CVE-2023-39141-LFI-ENUMERATOR&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Perform network-wide discovery to identify Ziahamza webui-aria2 deployments
      owner: SOC
      due: 24h
      evidence: Vulnerability affects all versions of the product.
  hunt_leads:
    - lead: Identify HTTP requests to webui-aria2 containing directory traversal sequences
      technique_id: T1083
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is a Local File Inclusion (LFI) exploit.
  mitigation_plan:
    - priority: immediate
      action: Block public access to webui-aria2 interface at the network perimeter
      owner: IT Operations
      addresses: CVE-2023-39141
      evidence: Remote exploit vector confirmed in vulnerability details.
---

CVE-2023-39141 is a high-severity local file inclusion (LFI) vulnerability affecting Ziahamza webui-aria2. An attacker can exploit this vulnerability without authentication or user interaction to read files from the host filesystem. A proof-of-concept tool has been published, enabling automated file enumeration. All versions of webui-aria2 are currently identified as affected.

## Impact

Successful exploitation results in unauthorized disclosure of sensitive files residing on the host system. This may include configuration files, credentials, or system information, depending on the service account privileges under which the webui-aria2 process is running.

## Recommendation

* Identify and inventory all instances of Ziahamza webui-aria2 within the environment.
* Restrict network access to webui-aria2 instances, ensuring they are not exposed to the public internet.
* Monitor web server logs for requests containing directory traversal patterns (e.g., ../) or suspicious file path enumeration attempts targeting webui-aria2 endpoints.
* Review the referenced GitHub Gist to understand the exploitation path and validate if internal WAF or IDS signatures can detect the documented exploit patterns.
