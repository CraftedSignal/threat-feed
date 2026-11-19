---
brief_id: brief-2024-11-02-wps-office-dll-hijack
event_id: brief-2024-11-02-wps-office-dll-hijack
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:be781523fc273d7bec966b754db27e042095442b65bda42489d6d1f72ec3690e
    summary: exploited:true; KEV CVE-2024-7262
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: WPS Office Exploitation via DLL Hijack
slug: 2024-11-wps-office-dll-hijack
description: The rule detects the loading of a remote library by the WPS Office promecefpluginhost.exe executable, which may indicate exploitation of CVE-2024-7262 or CVE-2024-7263 via DLL hijacking abusing the ksoqing custom protocol handler.
date: "2026-05-06T11:40:07Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2024-09-03T00:00:00Z"
  confidence: high
tags:
  - dll-hijacking
  - wps-office
  - cve-2024-7262
  - cve-2024-7263
  - execution
  - initial-access
vendors:
  - Kingsoft
products:
  - WPS Office
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1129
    technique_name: Shared Modules
cves:
  - id: CVE-2024-7262
    cvss: 7.8
    epss: 0.12362
    kev: true
    kev_status: "true"
  - id: CVE-2024-7263
    cvss: 7.8
    epss: 0.00146
    kev_status: unknown
references:
  - https://www.welivesecurity.com/en/eset-research/analysis-of-two-arbitrary-code-execution-vulnerabilities-affecting-wps-office/
  - https://mp.weixin.qq.com/s/F8hNyESBdKhwXkQPgtGpew
rules:
  - title: WPS Office Exploitation via DLL Hijack - Library Load
    description: Detects the load of a remote library by the WPS Office promecefpluginhost.exe executable from a suspicious path.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1129
      - T1203
    data_sources:
      - library
      - windows
  - title: WPS Office Exploitation via DLL Hijack - Image Load
    description: Detects the loading of a remote library by the WPS Office promecefpluginhost.exe executable, triggered by Image Load event from a suspicious path.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1129
      - T1203
    data_sources:
      - image_load
      - windows
rules_count: 2
updates:
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2024-7262
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

This detection identifies potential exploitation of CVE-2024-7262 or CVE-2024-7263 in WPS Office through DLL hijacking. The attack abuses the ksoqing custom protocol handler and involves loading a remote library by the `promecefpluginhost.exe` executable. The rule specifically looks for DLLs loaded from suspicious locations, such as temporary directories (`AppData\\Local\\Temp\\wps\\INetCache`), device paths (`\\Device\\Mup\\`), or UNC paths (`\\\\*`). Successful exploitation could lead to arbitrary code execution. This activity has been observed as of August 2024, and defenders should be aware that exploitation may occur through specially crafted WPS files or links.

## Attack Chain

1.  The user opens a malicious WPS Office document or clicks a specially crafted link.
2.  The `wps.exe` or `et.exe` process is launched to handle the document/link, potentially utilizing the "ksoqing" protocol.
3.  The WPS Office application attempts to load a plugin via `promecefpluginhost.exe`.
4.  Due to a DLL hijacking vulnerability (CVE-2024-7262 or CVE-2024-7263), `promecefpluginhost.exe` attempts to load a malicious DLL from a non-standard location such as `AppData\\Local\\Temp\\wps\\INetCache`, `\\Device\\Mup\\`, or a UNC path.
5.  The malicious DLL is loaded into the `promecefpluginhost.exe` process.
6.  The malicious DLL executes arbitrary code within the context of the `promecefpluginhost.exe` process.
7.  The attacker gains control of the compromised process and can perform actions such as downloading further malware, establishing persistence, or exfiltrating data.

## Impact

Successful exploitation of these vulnerabilities allows for arbitrary code execution within the context of the WPS Office application. This can lead to a complete compromise of the user's system, including data theft, installation of malware, and lateral movement within the network. There is no specific information on the number of victims or sectors targeted.

## Recommendation

*   Deploy the Sigma rule "WPS Office Exploitation via DLL Hijack - Library Load" to your SIEM to detect suspicious DLL loads by `promecefpluginhost.exe` (see rule below).
*   Deploy the Sigma rule "WPS Office Exploitation via DLL Hijack - Image Load" to your SIEM to detect suspicious image loads by `promecefpluginhost.exe` (see rule below).
*   Monitor network connections originating from `promecefpluginhost.exe` for suspicious outbound traffic.
*   Upgrade WPS Office to a vendor-supported release that remediates both CVE-2024-7262 and CVE-2024-7263.
*   Enable Sysmon Event ID 7 (Image Loaded) to enhance visibility into DLL loading events.
