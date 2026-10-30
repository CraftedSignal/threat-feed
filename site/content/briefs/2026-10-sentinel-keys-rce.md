---
brief_id: brief-2026-10-30-sentinel-keys-rce
event_id: brief-2026-10-30-sentinel-keys-rce
revision: 1
activity_at: "2026-10-30T23:04:51Z"
title: Thales Sentinel Keys Server Remote Code Execution (CVE-2026-78403)
slug: 2026-10-sentinel-keys-rce
description: An unauthenticated stack-based buffer overflow in Thales Sentinel Keys Server allows remote attackers to achieve code execution with SYSTEM privileges by sending a maliciously crafted HTTP request.
date: "2026-10-30T23:04:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:thales:sentinel_keys_server:*:*:*:*:*:*:*:*
vendors:
  - Thales
products:
  - Sentinel Keys Server (< 1.3.8.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated stack buffer overflow in Sentinel Keys Server allows RCE as SYSTEM.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: An attacker may craft an HTTP request and send it to Sentinel Keys Server. It may lead to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-78403
    cvss: 9.8
    kev_status: "false"
references:
  - https://supportportal.thalesgroup.com/csm?id=kb_article_view&sys_kb_id=50fc9f3b3b005f10bba8b41864e45a61&sysparm_article=KB0031216
  - https://sploitus.com/exploit?id=CVE-2026-78403
  - https://sploitus.com/exploit?id=CVE-2026-78403&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Sentinel Keys Server to 1.3.8.0 or later
      owner: IT Operations
      due: 24h
      evidence: Thales KB0031216
  hunt_leads:
    - lead: Identify abnormally large HTTP requests directed at Sentinel Keys Server service ports
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Network traffic logs (URI length/header size)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sentinel Keys Server does not check the length of the first field in the HTTP request.
  mitigation_plan:
    - priority: immediate
      action: Apply network ACLs to restrict service access
      owner: IT Operations
      addresses: Sentinel Keys Server network exposure
      evidence: Vulnerability is accessible via network
---

Thales Sentinel Keys Server is affected by a stack-based buffer overflow vulnerability (CVE-2026-78403) due to improper length validation of the first field in incoming HTTP requests. An unauthenticated attacker can exploit this via the network to execute arbitrary code as NT AUTHORITY\SYSTEM. This vulnerability affects Sentinel Keys Server versions prior to 1.3.8.0.

## Impact
Successful exploitation grants an attacker full remote code execution on the underlying Windows system with SYSTEM-level privileges.

## Recommendation
- Update Thales Sentinel Keys Server to version 1.3.8.0 or later immediately.
- Until patching, restrict network access to the Sentinel Keys Server service to authorized administrative IP addresses only.
- Review web server access logs for anomalous, high-length HTTP request headers or unusually long request lines directed at the service.
