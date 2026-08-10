---
title: ClamAV Vulnerabilities Affecting Cisco Secure Endpoint Products
slug: 2026-08-cisco-clamav-vulnerabilities
description: Multiple Cisco Secure Endpoint products are affected by vulnerabilities within the integrated ClamAV engine, necessitating immediate review and patching as recommended by the vendor.
date: "2026-08-10T19:30:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Cisco
products:
  - Secure Endpoint Connector for Linux
  - Secure Endpoint Connector for Mac
  - Secure Endpoint Connector for Windows
  - Secure Endpoint Private Cloud
references:
  - https://cyber.gc.ca/en/alerts-advisories/cisco-security-advisory-av26-794
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26
iocs:
  - type: url
    value: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26
ioc_counts:
  url: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Inventory and patch all Cisco Secure Endpoint deployments
      owner: IT Operations
      due: 72h
      evidence: Cisco security advisory AV26-794
---

Cisco has released a security advisory (AV26-794) identifying vulnerabilities originating from the third-party ClamAV engine integrated into various Cisco Secure Endpoint products. The affected software includes the Secure Endpoint Connector for Linux, macOS, and Windows, as well as Cisco Secure Endpoint Private Cloud versions prior to 8.4.5.30483. These vulnerabilities potentially expose organizations to remote code execution or denial of service conditions common to flawed antivirus engine parsing routines. As of August 2026, administrators should prioritize updating these instances to the latest available versions to remediate the underlying engine flaws. Given the ubiquity of Secure Endpoint in enterprise environments, failure to patch could allow unauthenticated attackers to trigger crashes or gain unauthorized execution on protected endpoints.

## Impact

Successful exploitation of these vulnerabilities could result in the compromise of endpoint integrity, service disruption, or unauthorized system access. These security products are deployed across a wide range of enterprise environments; potential impacts include wide-scale denial of service on security infrastructure or complete endpoint compromise if remote code execution is achieved.

## Recommendation

- Audit all security infrastructure to identify instances of Cisco Secure Endpoint Connector running versions affected by the ClamAV engine vulnerabilities.
- Apply the vendor-provided updates for Cisco Secure Endpoint Private Cloud (ensuring version is 8.4.5.30483 or higher) and update all desktop/server connectors via the Cisco management console.
- Review the official Cisco security advisory (cisco-sa-clamav-WuuvVd26) for specific patch release notes and versioning details.
