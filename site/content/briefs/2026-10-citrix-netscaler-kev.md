---
title: Active Exploitation of Citrix NetScaler Buffer Vulnerability (CVE-2026-88779)
slug: 2026-10-citrix-netscaler-kev
description: CISA has added CVE-2026-88779, a memory buffer vulnerability in Citrix NetScaler, to the Known Exploited Vulnerabilities (KEV) catalog due to confirmed in-the-wild exploitation.
date: "2026-10-04T20:49:54Z"
lastmod: "2026-10-05T00:48:27Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cisa-kev
  - citrix
  - netscaler
  - remote-code-execution
vendors:
  - Citrix
products:
  - NetScaler (< 14.1-73.41)
  - NetScaler ADC (< 14.1-73.41)
  - NetScaler Gateway (< 14.1-73.41)
cves:
  - id: CVE-2026-88779
references:
  - https://www.cisa.gov/news-events/alerts/2026/10/04/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-88779
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch NetScaler to 14.1-73.41 or later
      owner: IT Operations
      due: 24h
      evidence: CISA KEV Catalog addition mandates rapid remediation per BOD 26-04
  hunt_leads:
    - lead: Inspect logs for large, malformed HTTP payloads targeting NetScaler management or gateway interfaces
      data_needed:
        - Web server access logs
        - Appliance internal logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-88779 is a memory buffer vulnerability indicative of exploitation via malformed payloads
  mitigation_plan:
    - priority: immediate
      action: Update NetScaler to 14.1-73.41 or later
      owner: IT Operations
      addresses: CVE-2026-88779
      evidence: CISA KEV requirement
updates:
  - at: "2026-10-05T00:48:27Z"
    level: L1
    summary: new product
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-88779
---

CISA has officially added CVE-2026-88779, a vulnerability categorized as an Improper Restriction of Operations within the Bounds of a Memory Buffer in Citrix NetScaler, to its Known Exploited Vulnerabilities (KEV) Catalog. This addition is based on validated evidence of active exploitation by malicious cyber actors. Vulnerabilities of this class frequently lead to unauthorized remote code execution or system instability by corrupting memory within the application process space. The inclusion in the KEV Catalog triggers requirements under Binding Operational Directive (BOD) 26-04 for federal agencies to prioritize remediation on internet-facing assets. Organizations utilizing Citrix NetScaler must assess their exposure and apply available vendor patches as a priority, given the confirmed active threat environment.

## Impact

Successful exploitation of CVE-2026-88779 allows attackers to manipulate memory buffers within Citrix NetScaler, potentially resulting in unauthorized access, service disruption, or remote code execution. Given the nature of Citrix NetScaler as an edge appliance, compromised systems provide attackers with a significant foothold into enterprise networks, enabling lateral movement and further data exfiltration.

## Recommendation

* Prioritize the immediate patching of all internet-facing Citrix NetScaler instances against CVE-2026-88779 as required by BOD 26-04.
* Audit perimeter logs for anomalous traffic patterns directed at NetScaler appliances, specifically looking for abnormally large payloads or malformed requests that could trigger buffer memory issues.
* Following remediation, perform a forensic review of logs to determine if the system was compromised prior to the patch application, as mandated by the risk-based vulnerability management requirements outlined in BOD 26-04.
