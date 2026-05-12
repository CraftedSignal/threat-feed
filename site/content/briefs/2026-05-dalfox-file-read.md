---
title: Dalfox Server Mode Unauthenticated Arbitrary File Read
slug: 2026-05-dalfox-file-read
description: Dalfox server mode is vulnerable to an unauthenticated arbitrary file read with out-of-band exfiltration via the `custom-payload-file` parameter, allowing attackers to read sensitive files on the host.
date: "2026-05-12T15:11:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - unauthenticated-access
  - file-read
  - ghsa
vendors:
  - GitHub
products:
  - dalfox/v2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1213
    technique_name: Data from Information Repositories
references:
  - https://github.com/advisories/GHSA-35wr-x7v6-9fv2
  - https://cwe.mitre.org/data/definitions/306.html
  - https://cwe.mitre.org/data/definitions/73.html
  - https://cwe.mitre.org/data/definitions/552.html
rules:
  - title: Detect Dalfox Unauthenticated File Read via API
    description: Detects CVE-2026-45088 exploitation — monitors HTTP POST requests to the /scan endpoint with the custom-payload-file parameter, indicating a potential file read attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1083
      - T1110
    data_sources:
      - webserver
  - title: Detect Dalfox API Server Startup Without API Key
    description: Detects Dalfox API server starting without an API key defined, which is a prerequisite for the CVE-2026-45088 vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1546.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Dalfox, when run in REST API server mode, is vulnerable to an unauthenticated arbitrary file read. The `custom-payload-file` field in `model.Options` is deserialized from the request body and used to read files. An attacker can exploit this by sending a POST request to the `/scan` endpoint with a `custom-payload-file` parameter pointing to a file on the server. Dalfox then reads the file line by line and includes each line as a payload in outbound HTTP requests directed at an attacker-controlled target URL. This vulnerability exists because the server, by default, does not require an API key. This allows an unauthenticated network attacker to exfiltrate the contents of arbitrary files readable by the dalfox process. The affected version is dalfox/v2 <= 2.12.0.

## Attack Chain

1.  Attacker sends a POST request to the `/scan` endpoint of the Dalfox REST API server (typically running on `0.0.0.0:6664`).
2.  The request includes a JSON body with the `url`, `options`, `custom-payload-file`, `skip-discovery`, and `param` fields set.
3.  The `custom-payload-file` field contains the path to the file the attacker wants to read (e.g., `/etc/hostname`).
4.  The `skip-discovery` option is set to `true`, and `param` is set to `["q"]` to bypass checks.
5.  Dalfox reads the specified file line by line using `voltFile.ReadLinesOrLiteral`.
6.  Each line of the file is embedded as the value of the `q` query parameter in a GET request to the attacker-controlled URL.
7.  Dalfox sends the HTTP GET request to the attacker's server, exfiltrating one line of the file.
8.  The attacker receives the file content via the query parameter of the HTTP GET request.

## Impact

Successful exploitation allows an attacker to read arbitrary files on the Dalfox host that the Dalfox process has access to. This includes sensitive data like SSH private keys, TLS certificates, `.env` files containing credentials, cloud credential files, and system configuration files. If combined with other vulnerabilities, such as the `found-action` RCE, the attacker could potentially gain full control of the server.

## Recommendation

*   Implement the preferred remediation: Apply a denylist of fields that should never be accepted from the REST API, as suggested in the source, to prevent attackers from abusing `CustomPayloadFile` and other sensitive parameters.
*   Require the `--api-key` flag at server startup, as suggested in the source, to mandate authentication for all API requests.
*   Deploy the Sigma rule `Detect Dalfox Unauthenticated File Read via API` to detect attempts to exploit this vulnerability by monitoring HTTP POST requests to the `/scan` endpoint with a `custom-payload-file` parameter.
