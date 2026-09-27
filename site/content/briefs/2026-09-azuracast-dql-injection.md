---
title: AzuraCast DQL Injection Vulnerability in sortOrder Parameter
slug: 2026-09-azuracast-dql-injection
description: AzuraCast versions prior to 0.23.8 are vulnerable to a DQL injection flaw in the sortOrder API parameter, allowing attackers to exfiltrate sensitive database contents.
date: "2026-09-27T03:05:15Z"
lastmod: "2026-09-27T03:06:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:azuracast:azuracast:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-application
  - vulnerability
  - webserver
  - broken-access-control
  - api-security
  - credential-exposure
vendors:
  - AzuraCast
products:
  - AzuraCast (< 0.23.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: AzuraCast before 0.23.8 contains a DQL injection vulnerability in the sortOrder API parameter.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An authenticated user with restricted View Station Page permissions can exploit this flaw to retrieve sensitive plaintext credentials.
    confidence_band: high
cves:
  - id: CVE-2026-100847
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100847
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100849
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100850
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100851
rules:
  - title: Detects CVE-2026-100847 Exploitation - DQL Injection Attempt
    description: Detects exploitation attempts against the AzuraCast sortOrder parameter by identifying DQL-specific keywords and characters in web requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-100849 Exploitation - Unauthorized Webhook Test Request
    description: Detects exploitation attempts against the AzuraCast test webhook endpoint, which can be abused to perform SSRF when coupled with malformed URL inputs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-100850 - AzuraCast SSRF and Local File Read
    description: Detects exploitation of CVE-2026-100850 by monitoring requests to the station queue API that contain indicators of local file path traversal or internal URI schemes.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Exploitation of CVE-2026-100851 - Broken Access Control in AzuraCast
    description: Detects potential exploitation attempts by monitoring for requests to the vulnerable API endpoint profile which leaks administrative credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
rules_count: 4
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade AzuraCast to version 0.23.8 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-100847 fix availability in version 0.23.8.
  mitigation_plan:
    - priority: immediate
      action: Upgrade AzuraCast to version 0.23.8 or later.
      owner: IT Operations
      addresses: CVE-2026-100847
      evidence: Source advisory specifies version 0.23.8 for remediation.
updates:
  - at: "2026-09-27T03:05:52Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-100849 Exploitation - Unauthorized Webhook Test Request'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100849
  - at: "2026-09-27T03:06:07Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-100850 - AzuraCast SSRF and Local File Read'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100850
  - at: "2026-09-27T03:06:15Z"
    level: L2
    summary: 'added detection rule: Detect Exploitation of CVE-2026-100851 - Broken Access Control in AzuraCast'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100851
---

AzuraCast versions before 0.23.8 are susceptible to a DQL injection vulnerability located within the 'sortOrder' API parameter of the 'AbstractSearchableListAction.php' file. An attacker can exploit this flaw by supplying specially crafted DQL (Doctrine Query Language) expressions via the 'sortOrder' parameter. Successful exploitation permits the attacker to bypass standard query logic, potentially leading to the unauthorized exfiltration of sensitive information from the application's database, including user credentials and station configuration settings. This vulnerability presents a significant risk to the integrity and confidentiality of the AzuraCast environment. Organizations should prioritize updating to version 0.23.8 or later to mitigate this risk.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to query and extract sensitive database contents. This could lead to the exposure of administrative user credentials and specific stream/station configuration data, potentially facilitating full application compromise or unauthorized control over broadcast settings.

## Recommendation

Update all AzuraCast instances to version 0.23.8 or later immediately to patch CVE-2026-100847. Detection engineering teams should monitor web access logs for anomalous, high-entropy content or SQL/DQL-like syntax (e.g., SELECT, FROM, JOIN, WHERE) within the 'sortOrder' query parameter of API requests.
