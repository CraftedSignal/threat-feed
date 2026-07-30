---
title: CVE-2026-54366 CentreStack XXE Injection
slug: 2026-07-centrestack-xxe
description: CentreStack versions prior to 17.4 are vulnerable to an unauthenticated XXE injection via the SharePoint storage configuration handler, allowing attackers to exfiltrate sensitive server-side files.
date: "2026-07-30T13:41:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xxe
  - vulnerability
  - web-application
vendors:
  - CentreStack
products:
  - CentreStack (< 17.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CentreStack before 17.4 contains an XML external entity (XXE) injection vulnerability that allows unauthenticated attackers to exfiltrate arbitrary files by supplying a malicious URL.
    confidence_band: high
cves:
  - id: CVE-2026-54366
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54366
rules:
  - title: Detect CVE-2026-54366 Exploitation Attempt
    description: Detects exploitation attempts against CVE-2026-54366 by identifying suspicious XML entities in POST requests to the StorageConfig endpoint
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CentreStack versions prior to 17.4 contain an XML external entity (XXE) injection vulnerability in the SharePoint storage configuration handler. This flaw allows an unauthenticated attacker to supply a malicious URL to the StorageConfig endpoint. The vulnerability exists because the application improperly processes user-supplied XML data without sufficient validation, permitting the inclusion of external DTD references. By sending a crafted request, an attacker can force the server to parse an external entity and exfiltrate the contents of local files out-of-band. This represents a significant risk, as the exfiltration of files such as Web.config can expose sensitive database credentials, configuration details, and cryptographic keys, leading to full system compromise or unauthorized access to backend storage.

## Attack Chain

1. Attacker identifies the target instance of CentreStack accessible via the internet.
2. Attacker crafts an XML payload containing a malicious external DTD reference targeting a local file (e.g., Web.config).
3. Attacker sends an unauthenticated HTTP POST request to the /StorageConfig endpoint of the CentreStack application.
4. The application processes the malicious XML payload within the SharePoint storage configuration handler.
5. The server performs an out-of-band request to the attacker-controlled DTD server as instructed by the XXE payload.
6. The server reads the target file content and includes it in the communication or triggers a side-channel exfiltration of the data.
7. The attacker captures the exfiltrated sensitive data, such as database credentials or encryption keys, from their controlled server.
8. Attacker uses the stolen credentials to gain persistent or elevated access to the CentreStack backend and associated storage environments.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files from the filesystem of the hosting server. In typical enterprise deployments, this leads to the compromise of Web.config files, resulting in the theft of database connection strings, administrative credentials, and cryptographic keys. This impact compromises the confidentiality of all data managed by the CentreStack instance and enables further lateral movement into linked storage services like SharePoint.

## Recommendation

1. Upgrade all instances of CentreStack to version 17.4 or later immediately to patch CVE-2026-54366.
2. Deploy the provided Sigma rule to webserver access logs to detect potential XXE probe attempts targeting the StorageConfig endpoint.
3. Review web server logs for HTTP requests to the StorageConfig endpoint originating from unexpected or untrusted external IP addresses.
4. If an instance was compromised, rotate all database credentials, API keys, and cryptographic secrets stored within Web.config and application settings.
