---
title: Unauthenticated JDBC Injection in AllData
slug: 2026-10-alldata-jdbc-injection
description: AllData versions 0.7.1 and earlier are vulnerable to unauthenticated JDBC injection via the /jobJdbcDatasource/test endpoint, enabling remote attackers to perform arbitrary file read via the MySQL allowLoadLocalInfile parameter.
date: "2026-10-16T18:46:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:alldata:alldata:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - jdbc-injection
  - data-exfiltration
vendors:
  - AllData
products:
  - AllData (<= 0.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: AllData through 0.7.1 contains an unauthenticated JDBC injection vulnerability that allows remote attackers to open arbitrary database connections.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can supply a MySQL JDBC URL with allowLoadLocalInfile=true pointing to an attacker-controlled server to read arbitrary files from the data-dts host.
    confidence_band: high
cves:
  - id: CVE-2026-111613
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111613
rules:
  - title: Detect CVE-2026-111613 Exploitation - JDBC Connection Test with Local Infile
    description: Detects exploitation attempts against CVE-2026-111613 by identifying POST requests to the /jobJdbcDatasource/test endpoint containing the allowLoadLocalInfile parameter.
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
    - IT Operations
  immediate_actions:
    - action: Patch AllData to a version > 0.7.1
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability affects versions through 0.7.1
    - action: Deploy Sigma rule for /jobJdbcDatasource/test monitoring
      owner: SOC
      due: 24h
      evidence: Rule targets the specific vulnerable endpoint identified in the source
  hunt_leads:
    - lead: Search logs for POST /jobJdbcDatasource/test from unauthorized external IPs
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated remote access via this endpoint
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /jobJdbcDatasource/test
      owner: IT Operations
      addresses: CVE-2026-111613
      evidence: Vulnerability is unauthenticated and remote
---

AllData through version 0.7.1 contains a critical JDBC injection vulnerability in the data-dts component. The flaw exists within the /jobJdbcDatasource/test endpoint, which fails to properly validate user-supplied jdbcUrl and jdbcDriverClass parameters. An unauthenticated remote attacker can exploit this by submitting a specially crafted MySQL JDBC connection string. By setting the allowLoadLocalInfile property to true, an attacker can coerce the application server into initiating a connection to an attacker-controlled MySQL server. Once the connection is established, the attacker can leverage the LOAD DATA LOCAL INFILE capability to extract arbitrary files from the AllData host filesystem, leading to the exposure of sensitive configuration data, credentials, or system files.

## Attack Chain

1. Attacker identifies the target AllData instance and the accessible /jobJdbcDatasource/test endpoint.
2. Attacker sets up a rogue, internet-accessible MySQL server configured to receive incoming connections.
3. Attacker sends an unauthenticated HTTP POST request to the target endpoint containing malicious JDBC parameters.
4. The jdbcUrl parameter is set to include the malicious server address and the enableLoadLocalInfile=true flag.
5. The target application initiates a database connection request to the attacker's server.
6. The attacker's server responds with a request for a file from the host filesystem.
7. The target host reads the requested file and exfiltrates its contents to the attacker's infrastructure.

## Impact

Successful exploitation allows for the unauthorized reading of arbitrary files from the AllData host. This can lead to the compromise of internal system security by exposing sensitive configuration files, environment variables, or private keys. The vulnerability is rated with a CVSS 3.1 base score of 7.5, indicating a significant risk to confidentiality.

## Recommendation

* Immediately upgrade AllData to a version beyond 0.7.1 that remediates this vulnerability.
* Monitor webserver access logs for POST requests to the /jobJdbcDatasource/test path originating from unauthorized or external IP addresses.
* Restrict network access to the AllData management interface and specifically the /jobJdbcDatasource/test endpoint to trusted internal networks only.
* Implement egress filtering on the AllData host to block unexpected outbound MySQL (3306) or database-related connection attempts to untrusted external destinations.
