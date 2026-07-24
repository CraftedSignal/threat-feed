---
title: Budibase MongoDB Datasource Vulnerability Allows Server Filesystem Existence/Read Oracle
slug: 2026-07-budibase-file-oracle
description: A vulnerability in Budibase's MongoDB datasource configuration allows authenticated attackers to specify arbitrary absolute server-side file paths for `tlsCertificateKeyFile` and `tlsCAFile`, enabling the `/api/datasources/verify` endpoint to act as an arbitrary-path existence/read oracle on the underlying multi-tenant server, distinguishing between existing and non-existing files and potentially exfiltrating certificate content.
date: "2026-07-24T21:21:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - budibase
  - vulnerability
  - file-read
  - information-disclosure
  - cloud
  - mongodb
vendors:
  - Budibase
products:
  - npm/@budibase/server <= 3.38.1
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This enables the /api/datasources/verify endpoint to act as an arbitrary-path existence/read oracle over the whole server filesystem.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: 'Existing files return a ''PEM routines'' error (the file was read but is not PEM); missing files return `ENOENT ... open ''<path>''` with the path echoed back. This confirms a real filesystem read at the attacker-chosen absolute path. Example: /etc/passwd'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: PEM/certificate files on the server -> Content exfiltratable via mutual-TLS to an attacker MongoDB server (mechanism)
    confidence_band: med
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The `/api/datasources/verify` endpoint acts as an arbitrary-path existence/read oracle.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-ppr4-5f46-j9c6
iocs:
  - type: domain
    value: hasinocompany.budibase.app
  - type: url
    value: https://hasinocompany.budibase.app/api/datasources/verify
ioc_counts:
  domain: 1
  url: 1
---

A high-severity vulnerability (GHSA-ppr4-5f46-j9c6) has been identified in Budibase, a low-code platform, specifically affecting versions of `npm/@budibase/server` up to and including `3.38.1`. This flaw allows an authenticated attacker with "builder" privileges to exploit the MongoDB datasource configuration. When configuring a new MongoDB datasource, the `tlsCertificateKeyFile` and `tlsCAFile` fields are passed directly to the MongoDB driver as server-side file paths without proper validation or confinement. By crafting a POST request to the `/api/datasources/verify` endpoint, an attacker can supply arbitrary absolute paths (e.g., `/etc/passwd`) within these fields. The server's differential error responses (a "PEM routines" error for existing, readable files versus an "ENOENT" error for non-existent files) create an arbitrary-path existence and read oracle across the entire server filesystem, including multi-tenant cloud environments. This enables malicious actors to discover sensitive system files and potentially exfiltrate the content of certificate-related files.

## Attack Chain

1. An authenticated attacker with builder role accesses the Budibase application.
2. The attacker crafts a malicious POST request to the `/api/datasources/verify` endpoint.
3. The request body includes a MongoDB datasource configuration where the `config.tlsCertificateKeyFile` or `config.tlsCAFile` parameter is set to an absolute path on the server's filesystem, such as `/etc/passwd` or `/root/.ssh/id_rsa`.
4. The Budibase server processes this request, passing the attacker-controlled absolute path directly to the underlying MongoDB driver for certificate verification.
5. The MongoDB driver attempts to access the specified file on the server's filesystem.
6. Based on the filesystem's response, Budibase returns a distinct error message: a "PEM routines::no start line" error if the file exists and is readable but not a valid PEM certificate, or an "ENOENT: no such file or directory, open '&lt;path>'" error if the file does not exist.
7. The attacker analyzes the returned error message to determine the existence and readability of arbitrary files, effectively using the endpoint as an information oracle.
8. If the targeted file is a certificate or PEM file, the attacker can configure the MongoDB connection string to an attacker-controlled server using mutual TLS, potentially leading to the exfiltration of the file's content.

## Impact

Successful exploitation of this vulnerability grants an authenticated attacker the ability to perform arbitrary-path existence and read oracle operations across the entire filesystem of the underlying multi-tenant cloud server. This allows for the discovery of sensitive server configuration files, secrets, and potentially the paths of other tenants. While not directly leading to remote code execution, the ability to confirm the existence and read parts of sensitive files like `/etc/passwd` or certificate files poses a significant information disclosure risk. In multi-tenant environments, this could lead to lateral movement or further compromise by exposing critical system details or credentials.

## Recommendation

* **Patch `npm/@budibase/server`**: Immediately upgrade `npm/@budibase/server` to a version greater than `3.38.1` to apply the vendor's recommended fixes.
* **Implement input validation and confinement**: Ensure that `tlsCertificateKeyFile` and `tlsCAFile` fields are disallowed as filesystem paths on managed/Cloud instances, or that any file references are confined to an allow-listed certificates directory and absolute/`..` paths are rejected.
* **Enable web application logging**: Review web server logs for POST requests to `/api/datasources/verify` that contain unexpected or absolute file paths in the request body, specifically within `tlsCertificateKeyFile` or `tlsCAFile` parameters.
* **Deploy SSRF protection**: Ensure that the MongoDB connection host is routed through an SSRF blacklist to prevent potential further exploitation paths, as recommended by the vendor.
