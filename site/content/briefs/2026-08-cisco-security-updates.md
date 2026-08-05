---
title: Cisco Security Updates - August 2026
slug: 2026-08-cisco-security-updates
description: Roundup of Cisco security advisories published in August 2026.
date: "2026-08-05T17:20:12Z"
lastmod: "2026-08-05T21:26:39Z"
type: threat
types:
  - threat
severities:
  - high
has_poc: true
tags:
  - roundup
vendors:
  - Cisco
products:
  - IOS XE Software
  - Catalyst SD-WAN
  - Integrated Management Controller
  - IOS Software
  - RoomOS
  - Catalyst SD-WAN Manager
  - Terminal Services Agent
cves:
  - id: CVE-2026-20267
    cvss: 9
  - id: CVE-2026-20272
    cvss: 9.8
  - id: CVE-2026-20310
    cvss: 9.1
  - id: CVE-2026-20200
    cvss: 8.8
  - id: CVE-2026-20263
    cvss: 8.6
  - id: CVE-2026-20268
    cvss: 8.6
  - id: CVE-2026-20269
    cvss: 8.6
  - id: CVE-2026-20273
    cvss: 8.6
  - id: CVE-2026-20301
    cvss: 8.6
  - id: CVE-2026-20313
    cvss: 7.7
  - id: CVE-2026-20311
    cvss: 6.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20272
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20310
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20124
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20200
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20263
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20268
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20269
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20271
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20273
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20301
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20312
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20313
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xe-webui-dos-PtAODAWW?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20IOS%20XE%20Software%20Web-Based%20Management%20Interface%20Denial%20of%20Service%20Vulnerability%26vs_k=1
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-xss-7EhBFxBp?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Integrated%20Management%20Controller%20Cross-Site%20Scripting%20Vulnerability%26vs_k=1
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-roomos-infodisc-qBXjfmWm?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20RoomOS%20Logging%20Subsystem%20Information%20Disclosure%20Vulnerability%26vs_k=1
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-infodis-SPuJBDCe?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Catalyst%20SD-WAN%20Manager%20Information%20Disclosure%20Vulnerability%26vs_k=1
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxe-V8NMuMZJ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20IOS%20XE%20Software%20Security%20Hardening%20Release:%20August%202026%26vs_k=1
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ts-agent-fw-bypass-MYBTMrev?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Terminal%20Services%20Agent%20Firewall%20Rules%20Bypass%20Vulnerability%26vs_k=1
iocs:
  - type: url
    value: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xe-webui-dos-PtAODAWW
  - type: url
    value: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-xss-7EhBFxBp
  - type: url
    value: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-roomos-infodisc-qBXjfmWm
  - type: url
    value: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-infodis-SPuJBDCe
  - type: url
    value: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxe-V8NMuMZJ
  - type: url
    value: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ts-agent-fw-bypass-MYBTMrev
ioc_counts:
  url: 6
updates:
  - at: "2026-08-05T21:26:30Z"
    level: L2
    summary: added CVE-2026-20313
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-xss-7EhBFxBp?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Integrated%20Management%20Controller%20Cross-Site%20Scripting%20Vulnerability%26vs_k=1
  - at: "2026-08-05T21:26:32Z"
    level: L1
    summary: new IOCs
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-roomos-infodisc-qBXjfmWm?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20RoomOS%20Logging%20Subsystem%20Information%20Disclosure%20Vulnerability%26vs_k=1
  - at: "2026-08-05T21:26:35Z"
    level: L1
    summary: new IOCs
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-infodis-SPuJBDCe?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Catalyst%20SD-WAN%20Manager%20Information%20Disclosure%20Vulnerability%26vs_k=1
  - at: "2026-08-05T21:26:37Z"
    level: L2
    summary: poc_available; added CVE-2026-20301
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxe-V8NMuMZJ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20IOS%20XE%20Software%20Security%20Hardening%20Release:%20August%202026%26vs_k=1
  - at: "2026-08-05T21:26:39Z"
    level: L1
    summary: new IOCs
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ts-agent-fw-bypass-MYBTMrev?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Terminal%20Services%20Agent%20Firewall%20Rules%20Bypass%20Vulnerability%26vs_k=1
---

This roundup covers 17 Cisco security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Catalyst SD-WAN, Catalyst SD-WAN Manager, IOS Software, IOS XE Software, Integrated Management Controller, RoomOS.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-20267 | 9.0 | IOS XE Software | Cisco IOS XE Software contains multiple internally discovered vulnerabilities characterized by improper access control (CWE-284). These vulnerabilities were identified during an internal security review and addressed through software hardening releases, carrying a CVSS base score of 9.0. |
| CVE-2026-20272 | 9.8 | IOS XE Software | CVE-2026-20272 represents a critical vulnerability in Cisco IOS XE Software, identified through internal security reviews as an issue involving improper neutralization of special elements, classified under CWE-74. With a CVSS base score of 9.8, the vulnerability allows for potential remote command injection, requiring immediate patching as part of Cisco's software hardening releases. |
| CVE-2026-20310 | 9.1 | Catalyst SD-WAN | Cisco Catalyst SD-WAN is affected by a vulnerability (CVE-2026-20310) resulting from improper link resolution before file access, categorized as CWE-59. This internally discovered issue prompted security hardening updates for the affected platform. |
| CVE-2026-20124 | 0.0 | IOS XE Software | CVE-2026-20124 is a denial of service vulnerability in the SNMP subsystem of Cisco IOS XE Software. An authenticated remote attacker with valid SNMP community strings (v1/v2c) or credentials (v3) can send a malformed SNMP request, causing the device to unexpectedly reload. Detection should focus on monitoring SNMP request traffic for anomalies or malformed packets targeting the SNMP subsystem. |
| CVE-2026-20200 | 8.8 | Integrated Management Controller | Cisco IMC contains a vulnerability in its web-based management interface stemming from improper input validation. An authenticated remote attacker with low privileges can leverage this flaw to perform command injection, resulting in the execution of arbitrary commands with root-level privileges on the underlying operating system. |
| CVE-2026-20263 | 8.6 | IOS XE Software | A vulnerability in the Blocks Extensible Exchange Protocol (BEEP) feature of Cisco IOS XE Software allows unauthenticated remote attackers to trigger a device reload via a crafted BEEP SOAP request, resulting in a denial-of-service (DoS) condition. |
| CVE-2026-20268 | 8.6 | IOS XE Software | Cisco IOS XE Software contains vulnerabilities related to improper restriction of operations within the bounds of a memory buffer, categorized under CWE-119. These issues were discovered during an internal security review and addressed via software hardening releases, carrying a CVSS v3.1 base score of 8.6. |
| CVE-2026-20269 | 8.6 | IOS XE Software | Cisco IOS XE Software contains multiple internally discovered vulnerabilities related to improper control of a resource through its lifetime, classified under CWE-664. These issues were identified during a proactive internal security review and have been addressed in software hardening releases. |
| CVE-2026-20271 | 0.0 | IOS XE Software | Cisco IOS XE Software contains multiple vulnerabilities related to insufficient control flow management, categorized under CWE-691. These vulnerabilities were identified through an internal security review, and Cisco has released software updates to address the underlying issues. |
| CVE-2026-20273 | 8.6 | IOS XE Software | CVE-2026-20273 refers to an improper input validation vulnerability (CWE-20) in Cisco IOS XE Software. With a CVSS base score of 8.6, this vulnerability is exploitable remotely by an unauthenticated attacker, potentially leading to a denial-of-service condition (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H). |
| CVE-2026-20301 | 0.0 | IOS Software | A vulnerability in the Extensible Messaging Client Protocol (XMCP) implementation within Cisco IOS and IOS XE software allows unauthenticated, remote attackers to trigger a device reload via malformed packets, resulting in a denial-of-service condition. |
| CVE-2026-20312 | 0.0 | Catalyst SD-WAN | Cisco Catalyst SD-WAN software contains a vulnerability identified as CVE-2026-20312 involving the cleartext storage of sensitive information, classified under CWE-312. This vulnerability was identified during an internal security review and addressed through a software hardening release. |
| CVE-2026-20313 | 7.7 | Catalyst SD-WAN | Cisco Catalyst SD-WAN is affected by a vulnerability involving improper link resolution before file access, categorized under CWE-1284. This vulnerability was identified during an internal security review and addressed via software hardening releases. |
| CVE-2026-20311 | 6.3 | IOS XE Software | A vulnerability in the web-based management interface of Cisco IOS XE Software allows an authenticated, low-privileged remote attacker to trigger a denial-of-service condition. By submitting a malformed certificate to the interface, an attacker can cause the device to reload, resulting in an unexpected service disruption. Cisco has released software updates to address this flaw. |
| CVE-2026-20198 | 0.0 | Integrated Management Controller | A cross-site scripting (XSS) vulnerability exists in the web-based management interface of the Cisco Integrated Management Controller due to improper input validation. An authenticated remote attacker can exploit this by convincing a user to interact with a malicious link, potentially leading to arbitrary script execution within the victim's browser context. |
| CVE-2026-20289 | 0.0 | RoomOS | A vulnerability in the logging subsystem of Cisco RoomOS allows an authenticated, local attacker with low privileges to access sensitive information, such as user login credentials, by enabling specific logging levels and accessing system logs. There are no workarounds available, and patching is required. |
| CVE-2026-20294 | 0.0 | Catalyst SD-WAN Manager | An information disclosure vulnerability exists in the web-based management interface of Cisco Catalyst SD-WAN Manager due to insufficient access control on specific template types. Authenticated attackers with low privileges can exploit this to view sensitive authentication credentials in clear text within local or remote logs, potentially leading to escalation of privilege and further infrastructure compromise. |


## CVE-2026-20267

Cisco IOS XE Software contains multiple internally discovered vulnerabilities characterized by improper access control (CWE-284). These vulnerabilities were identified during an internal security review and addressed through software hardening releases, carrying a CVSS base score of 9.0.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20267

## CVE-2026-20272

CVE-2026-20272 represents a critical vulnerability in Cisco IOS XE Software, identified through internal security reviews as an issue involving improper neutralization of special elements, classified under CWE-74. With a CVSS base score of 9.8, the vulnerability allows for potential remote command injection, requiring immediate patching as part of Cisco's software hardening releases.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20272

## CVE-2026-20310

Cisco Catalyst SD-WAN is affected by a vulnerability (CVE-2026-20310) resulting from improper link resolution before file access, categorized as CWE-59. This internally discovered issue prompted security hardening updates for the affected platform.

Affected products:
- Catalyst SD-WAN

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20310

## CVE-2026-20124

CVE-2026-20124 is a denial of service vulnerability in the SNMP subsystem of Cisco IOS XE Software. An authenticated remote attacker with valid SNMP community strings (v1/v2c) or credentials (v3) can send a malformed SNMP request, causing the device to unexpectedly reload. Detection should focus on monitoring SNMP request traffic for anomalies or malformed packets targeting the SNMP subsystem.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20124

## CVE-2026-20200

Cisco IMC contains a vulnerability in its web-based management interface stemming from improper input validation. An authenticated remote attacker with low privileges can leverage this flaw to perform command injection, resulting in the execution of arbitrary commands with root-level privileges on the underlying operating system.

Affected products:
- Integrated Management Controller

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20200

## CVE-2026-20263

A vulnerability in the Blocks Extensible Exchange Protocol (BEEP) feature of Cisco IOS XE Software allows unauthenticated remote attackers to trigger a device reload via a crafted BEEP SOAP request, resulting in a denial-of-service (DoS) condition.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20263

## CVE-2026-20268

Cisco IOS XE Software contains vulnerabilities related to improper restriction of operations within the bounds of a memory buffer, categorized under CWE-119. These issues were discovered during an internal security review and addressed via software hardening releases, carrying a CVSS v3.1 base score of 8.6.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20268

## CVE-2026-20269

Cisco IOS XE Software contains multiple internally discovered vulnerabilities related to improper control of a resource through its lifetime, classified under CWE-664. These issues were identified during a proactive internal security review and have been addressed in software hardening releases.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20269

## CVE-2026-20271

Cisco IOS XE Software contains multiple vulnerabilities related to insufficient control flow management, categorized under CWE-691. These vulnerabilities were identified through an internal security review, and Cisco has released software updates to address the underlying issues.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20271

## CVE-2026-20273

CVE-2026-20273 refers to an improper input validation vulnerability (CWE-20) in Cisco IOS XE Software. With a CVSS base score of 8.6, this vulnerability is exploitable remotely by an unauthenticated attacker, potentially leading to a denial-of-service condition (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H).

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20273

## CVE-2026-20301

A vulnerability in the Extensible Messaging Client Protocol (XMCP) implementation within Cisco IOS and IOS XE software allows unauthenticated, remote attackers to trigger a device reload via malformed packets, resulting in a denial-of-service condition.

Affected products:
- IOS Software
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20301

## CVE-2026-20312

Cisco Catalyst SD-WAN software contains a vulnerability identified as CVE-2026-20312 involving the cleartext storage of sensitive information, classified under CWE-312. This vulnerability was identified during an internal security review and addressed through a software hardening release.

Affected products:
- Catalyst SD-WAN

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20312

## CVE-2026-20313

Cisco Catalyst SD-WAN is affected by a vulnerability involving improper link resolution before file access, categorized under CWE-1284. This vulnerability was identified during an internal security review and addressed via software hardening releases.

Affected products:
- Catalyst SD-WAN

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20313

## CVE-2026-20311

A vulnerability in the web-based management interface of Cisco IOS XE Software allows an authenticated, low-privileged remote attacker to trigger a denial-of-service condition. By submitting a malformed certificate to the interface, an attacker can cause the device to reload, resulting in an unexpected service disruption. Cisco has released software updates to address this flaw.

Affected products:
- IOS XE Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xe-webui-dos-PtAODAWW?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20IOS%20XE%20Software%20Web-Based%20Management%20Interface%20Denial%20of%20Service%20Vulnerability%26vs_k=1

## CVE-2026-20198

A cross-site scripting (XSS) vulnerability exists in the web-based management interface of the Cisco Integrated Management Controller due to improper input validation. An authenticated remote attacker can exploit this by convincing a user to interact with a malicious link, potentially leading to arbitrary script execution within the victim's browser context.

Affected products:
- Integrated Management Controller

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-xss-7EhBFxBp?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Integrated%20Management%20Controller%20Cross-Site%20Scripting%20Vulnerability%26vs_k=1

## CVE-2026-20289

A vulnerability in the logging subsystem of Cisco RoomOS allows an authenticated, local attacker with low privileges to access sensitive information, such as user login credentials, by enabling specific logging levels and accessing system logs. There are no workarounds available, and patching is required.

Affected products:
- RoomOS

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-roomos-infodisc-qBXjfmWm?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20RoomOS%20Logging%20Subsystem%20Information%20Disclosure%20Vulnerability%26vs_k=1

## CVE-2026-20294

An information disclosure vulnerability exists in the web-based management interface of Cisco Catalyst SD-WAN Manager due to insufficient access control on specific template types. Authenticated attackers with low privileges can exploit this to view sensitive authentication credentials in clear text within local or remote logs, potentially leading to escalation of privilege and further infrastructure compromise.

Affected products:
- Catalyst SD-WAN Manager

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-infodis-SPuJBDCe?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Catalyst%20SD-WAN%20Manager%20Information%20Disclosure%20Vulnerability%26vs_k=1
