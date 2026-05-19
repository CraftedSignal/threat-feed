---
title: auth-fetch-mcp SSRF and Disk Exfiltration Vulnerability
slug: 2026-05-auth-fetch-mcp-ssrf
description: The auth-fetch-mcp package is vulnerable to server-side request forgery (SSRF) and disk exfiltration due to unvalidated URLs in the `download_media` and `auth_fetch` tools, allowing an attacker to fetch internal resources, cloud metadata, or loopback addresses, potentially leading to credential theft, internal service enumeration, and sensitive information disclosure.
date: "2026-05-19T15:48:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - disk-exfiltration
  - auth-fetch-mcp
products:
  - auth-fetch-mcp (<= 3.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-hv85-774v-26fg
iocs:
  - type: ip
    value: 169.254.169.254
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
  - type: hash_sha256
    value: 4cea53f1a618581fc67f9a8bd07a7a2b22274f42cdbf7f3c658519673aaf7568
ioc_counts:
  hash_sha256: 1
  ip: 1
  url: 1
rules:
  - title: Detect auth-fetch-mcp download_media Disk Write to Unusual Directory
    description: Detects writing files to unusual directories via download_media, which may indicate a SSRF and data exfiltration attempt.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - exfiltration
    techniques:
      - T1041
      - T1592
    data_sources:
      - process_creation
      - windows
  - title: Detect auth-fetch-mcp auth_fetch Tool Execution with Internal IP Address
    description: Detects the execution of the auth_fetch tool with a URL containing an internal IP address, potentially indicating SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1016
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `auth-fetch-mcp` package is vulnerable to server-side request forgery (SSRF) and disk exfiltration. The `download_media` and `auth_fetch` tools within the package accept arbitrary URLs without proper validation, allowing a malicious MCP client to force the server to fetch internal resources, cloud metadata endpoints, or loopback addresses. This vulnerability can be exploited to steal cloud credentials, enumerate internal services, and access sensitive information. The `download_media` tool further exacerbates the risk by writing the fetched content to a user-controlled output directory, enabling data exfiltration. This vulnerability affects versions 3.0.0 and earlier of the `auth-fetch-mcp` package.

## Attack Chain

1.  An attacker crafts a malicious prompt that instructs the LLM-based MCP client to call either the `auth_fetch` or `download_media` tool.
2.  The malicious prompt includes a URL targeting an internal resource, such as a cloud metadata endpoint (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`), a loopback service (e.g., `http://127.0.0.1:6379`), or an internal admin page (e.g., `http://192.168.0.1`).
3.  If the `auth_fetch` tool is called, the `url` is passed directly to `page.goto` function in `src/browser.ts`, causing the Playwright browser to navigate to the specified URL without validation.
4.  The `auth_fetch` tool extracts the DOM content of the fetched page using the `extractContent` function and returns it to the attacker.
5.  If the `download_media` tool is called, the provided URLs are iterated, and `ctx.request.get(url)` is called for each URL in `src/tools.ts`, fetching the content without validation.
6.  The response body from the fetched URL is written to a file in the user-specified `output_dir` using `fs.writeFileSync` in `src/tools.ts`.
7.  The attacker retrieves the fetched data from either the `auth_fetch` tool's response or from the files written to disk by the `download_media` tool.
8.  The attacker obtains sensitive information, such as cloud credentials, internal service configurations, or other confidential data.

## Impact

Successful exploitation can lead to the theft of cloud credentials, allowing attackers to gain unauthorized access to cloud resources. Internal service enumeration can reveal valuable information about the network infrastructure and potential attack vectors. Access to loopback services can expose sensitive data or allow for further exploitation of vulnerable applications. The disk-write side channel in `download_media` can enable data exfiltration to shared directories, potentially impacting co-tenant processes. The scope of impact depends on the privileges and access controls of the MCP server environment, the sensitivity of accessible internal resources, and the extent to which the LLM can be prompted to expose these vulnerabilities.

## Recommendation

*   Implement URL validation in both the `auth_fetch` and `download_media` tools to prevent SSRF attacks, using the `assertSafeUrl` function described in the advisory. Apply the validation at `tools.ts:236` and `browser.ts:53`.
*   Restrict the `output_dir` parameter in the `download_media` tool to a fixed root directory to prevent writing files to arbitrary locations.
*   Monitor network connections originating from the MCP server for connections to internal IP addresses (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16) using a network monitoring solution.
*   Deploy the Sigma rule "Detect auth-fetch-mcp download_media Disk Write to Unusual Directory" to detect potential exfiltration attempts via unusual output directories.
*   Block the IOCs listed in the IOC table at your network perimeter to prevent the exploitation of the SSRF vulnerability.
