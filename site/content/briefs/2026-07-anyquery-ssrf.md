---
title: Anyquery Server-Side Request Forgery via Unrestricted SQLite Virtual Table Modules
slug: 2026-07-anyquery-ssrf
description: Unauthenticated attackers can exploit a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-54628) in Anyquery's `server` mode (versions prior to 0.4.5) by creating SQLite virtual tables that fetch internal network resources or cloud metadata, leading to internal network mapping and exfiltration of sensitive information like cloud credentials.
date: "2026-07-14T20:39:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - vulnerability
  - anyquery
products:
  - Anyquery (< 0.4.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers connecting to the MySQL-compatible server port can create virtual tables pointing to internal network endpoints or Cloud Metadata IPs
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: This allows attackers to perform Server-Side Request Forgery (SSRF), bypassing external firewalls to scan internal ports and exfiltrate cloud credentials.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This allows attackers to perform Server-Side Request Forgery (SSRF), bypassing external firewalls to scan internal ports and exfiltrate cloud credentials.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-hwrq-8wxh-q4xv
rules:
  - title: Detect CVE-2026-54628 Exploitation - Anyquery Outbound Connection to Cloud Metadata IP
    description: Detects CVE-2026-54628 exploitation by monitoring outbound network connections from the 'anyquery' process to known cloud metadata IP addresses (e.g., AWS IMDS).
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1595.002
    data_sources:
      - network_connection
      - linux
  - title: Detect CVE-2026-54628 Exploitation - Anyquery Outbound Connection to Private IP Ranges
    description: Detects CVE-2026-54628 exploitation by monitoring outbound network connections from the 'anyquery' process to RFC1918 private IP address ranges, indicating an attempt to scan or interact with internal network resources.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1595.002
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Anyquery, a tool for querying various data sources, contains a critical Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-54628, in its `server` mode. When `anyquery server` is launched, it exposes a MySQL-compatible interface. Versions prior to 0.4.5 allow unauthenticated attackers to create dynamic virtual tables using modules such as `json_reader` or `log_reader`. These modules leverage `go-getter` to fetch URLs without restricting access to local (127.0.0.0/8), private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), or cloud metadata (169.254.169.254) IP addresses. This allows attackers to bypass network segmentation, scan internal ports, interact with internal APIs, and exfiltrate cloud credentials (e.g., AWS IAM tokens) from the underlying host. The vulnerability poses a significant risk to the confidentiality of internal network data and cloud environments.

## Attack Chain

1. An unauthenticated attacker initiates a MySQL client connection to the vulnerable Anyquery server running in `server` mode (e.g., `anyquery server --host 0.0.0.0 --port 8070`).
2. The attacker executes a crafted `CREATE VIRTUAL TABLE` SQL statement using an unrestricted virtual table module like `log_reader` or `json_reader`.
3. The `CREATE VIRTUAL TABLE` statement includes a maliciously crafted URL pointing to an internal resource, such as `http://169.254.169.254/latest/meta-data/` for AWS credentials or `http://localhost:8000/admin` for an internal web application.
4. The Anyquery server, via its internal `go-getter` library, performs an unconstrained HTTP GET request from the server's context to the specified internal or metadata URL.
5. The Anyquery server receives the HTTP response containing potentially sensitive data from the internal resource.
6. The attacker executes a `SELECT * FROM <virtual_table_name>` query against the newly created virtual table.
7. Anyquery returns the fetched HTTP response content directly as rows within the SQL query result.
8. The attacker successfully retrieves and exfiltrates sensitive information, such as cloud IAM credentials, internal API responses, or details of the internal network architecture.

## Impact

The successful exploitation of CVE-2026-54628 in Anyquery's `server` mode leads to a high confidentiality impact. Attackers can exfiltrate sensitive internal network data, such as responses from internal REST APIs, and critical cloud credentials (e.g., AWS IAM tokens from metadata services), bypassing external firewall restrictions. This enables unauthorized access to other internal systems and cloud resources. While the integrity impact is rated as low (due to potential interaction with state-changing internal APIs), the primary concern is the unconstrained access to confidential information. The vulnerability has a CVSSv3.1 score of 8.6 (High).

## Recommendation

* Patch CVE-2026-54628 by upgrading Anyquery to version 0.4.5 or later immediately.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious outbound network connections.
* Enable network connection logging for the `anyquery` process to detect attempts to connect to internal or metadata IP addresses.
* Monitor your DNS and proxy logs for `anyquery` process activity connecting to `169.254.169.254` (AWS metadata service) and other cloud metadata IPs.
