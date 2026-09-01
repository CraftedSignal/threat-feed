---
title: Threat Actors Impersonate AI Crawlers to Exfiltrate Sensitive Credentials
slug: 2026-08-ai-crawler-impersonation
description: Threat actors are using forged User-Agent strings to masquerade as AI crawlers from OpenAI, Anthropic, and other firms to scan for and exfiltrate environment files and cloud credentials from misconfigured web servers.
date: "2026-08-28T15:12:38Z"
lastmod: "2026-09-01T00:08:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vitejs:vite:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-THUMPBO-CVE-2025-30208-EXP&utm_source=rss&utm_medium=rss
tags:
  - credential-theft
  - web-scraping
  - scanning
  - reconnaissance
vendors:
  - Vite
products:
  - Vite (< 4.5.10, 5.4.15, 6.0.12, 6.1.2, 6.2.3)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595.002
    technique_name: Vulnerability Scanning
    evidence: GreyNoise is observing automated scanners posing as the web crawlers of OpenAI, Anthropic, DeepSeek, and Fortune 500 companies.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: A cluster of scanners impersonating 13 AI crawlers from eight companies requested .env files, cloud access keys, private keys and password stores.
    confidence_band: high
cves:
  - id: CVE-2025-30208
    cvss: 5.3
    epss: 0.74784
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-THUMPBO-CVE-2025-30208-EXP&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Unauthorized Access to Sensitive Configuration Files
    description: Detects HTTP GET requests for sensitive configuration files often targeted by credential-harvesting scanners
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Vite to 6.2.3 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2025-30208 remediation advice
    - action: Implement monitoring for access to /.env, /.git, and cloud credential paths
      owner: SOC
      due: 24h
      evidence: GreyNoise recommendation for Security Operations
  mitigation_plan:
    - priority: immediate
      action: Validate crawler requests against official IP address manifests rather than User-Agent strings
      owner: IT Operations
      addresses: All web applications
      evidence: GreyNoise recommendation for Security Leadership
updates:
  - at: "2026-09-01T00:08:36Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-THUMPBO-CVE-2025-30208-EXP&utm_source=rss&utm_medium=rss
---

GreyNoise has identified a campaign involving automated scanners impersonating legitimate AI crawlers, including those from OpenAI, Anthropic, and DeepSeek. These actors use forged User-Agent strings - matching character-for-character with known crawlers like ClaudeBot - to bypass simple access controls that rely solely on the User-Agent header. Unlike legitimate bots, these scanners do not request /robots.txt files and originate from IP addresses that do not match the published IP ranges of the impersonated organizations.

The attackers specifically target sensitive configuration files and credentials, including .env files, cloud access keys, private keys, and password stores. This activity also includes attempts to exploit CVE-2025-30208 in Vite, an arbitrary file disclosure vulnerability. The scale of this campaign is significant, involving hundreds of distinct IP addresses spread across different network ranges, indicating a distributed and highly automated infrastructure. Defenders should transition from User-Agent-based allowlisting to a model that validates both the identity and the source IP address of incoming crawler requests.

## Attack Chain

1. Attacker reconnaissance phase identifies misconfigured web servers hosting sensitive files like .env or .git configurations.
2. Attacker crafts HTTP requests using forged User-Agent headers mimicking legitimate AI crawlers (e.g., Anthropic's ClaudeBot or OpenAI's GPTBot).
3. Attacker directs traffic from a distributed set of IP addresses (outside of legitimate provider ranges) toward target web servers.
4. Attacker attempts to bypass basic access controls that rely solely on string-matching the User-Agent header.
5. Attacker probes for known sensitive paths (e.g., /.env, /.aws/credentials) and attempts to exploit known vulnerabilities like CVE-2025-30208.
6. Attacker exfiltrates sensitive secrets and environment variables if the server returns valid file contents.

## Impact

Successful exploitation allows attackers to gain unauthorized access to critical infrastructure secrets, including cloud access keys, database credentials, and API tokens. This exposure can lead to lateral movement, data exfiltration, or complete takeover of cloud environments. The campaign targets a wide range of web platforms, and the automated nature suggests high-volume, opportunistic harvesting of credentials from any misconfigured internet-facing server.

## Recommendation

1. Audit all web access controls that rely solely on User-Agent strings; replace them with strict allowlists that validate the connecting IP address against the official JSON manifests provided by OpenAI, Anthropic, Amazon, and Google.
2. Deploy detections for requests to sensitive files (e.g., /.env, /.aws/credentials, /.git/config) coming from non-standard or unexpected client IP addresses.
3. Implement a log-based check to identify crawlers that never request /robots.txt, which is a strong indicator of non-benign bot activity.
4. Patch all Vite instances to version 6.2.3, 6.1.2, 6.0.12, 5.4.15, or 4.5.10 to remediate CVE-2025-30208.
5. Rotate all cloud access keys and API tokens that were hosted in the web root or potentially reachable via HTTP requests.
