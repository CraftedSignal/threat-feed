---
title: Mass-Scanning Campaign Exploits Vite Flaw to Extract Cloud Credentials
slug: 2026-09-vite-scanning
description: A mass-scanning campaign is actively exploiting CVE-2026-39364 in internet-exposed Vite development servers to bypass security restrictions and exfiltrate sensitive cloud credentials and configuration files.
date: "2026-09-15T12:29:18Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:vitejs:vite:*:*:*:*:*:*:*:*
  - cpe:2.3:a:vitejs:vite:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:voidzero:vite\+:*:*:*:*:*:node.js:*:*
vendors:
  - Vite
products:
  - Vite (development server)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The credential harvesting activity, observed in August 2026, has been found to leverage an exploit for CVE-2026-39364.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592.001
    technique_name: 'Software: System Information'
    evidence: Probing /proc/self/cwd/.env demonstrates an understanding of the deployment stack, reading the active .env file relative to the running process without needing to guess the absolute web application path.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595.002
    technique_name: Vulnerability Scanning
    evidence: Cybersecurity researchers have disclosed details of a mass-scanning campaign that has targeted Vite deployments siphon sensitive data.
    confidence_band: high
cves:
  - id: CVE-2026-39364
    cvss: 7.5
    epss: 0.01996
references:
  - https://thehackernews.com/2026/09/mass-scanning-campaign-exploits-vite.html
iocs:
  - type: ip
    value: 34.94.237.62
  - type: ip
    value: 104.28.219.193
ioc_counts:
  ip: 2
rules:
  - title: Detects CVE-2026-39364 Exploitation - Unauthorized File Read via Vite
    description: Detects attempts to bypass Vite's file system security restrictions by appending raw query parameters to the /@fs/ endpoint.
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
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to web application firewalls and SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms active exploitation of CVE-2026-39364.
    - action: Block IOC IPs 34.94.237.62 and 104.28.219.193 at edge firewalls.
      owner: SOC
      due: 24h
      evidence: Observed malicious infrastructure in source report.
  hunt_leads:
    - lead: Search web logs for /@fs/ with suspicious query parameters.
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies specific endpoints and parameters used in the exploit.
  mitigation_plan:
    - priority: immediate
      action: Identify and reconfigure Vite dev servers to avoid --host or server.host in public-facing contexts.
      owner: IT Operations
      addresses: CVE-2026-39364
      evidence: Source advises that Vite binds to localhost by default; exposure is caused by misconfiguration.
---

Since August 2026, threat actors have been conducting a mass-scanning campaign targeting Vite development servers exposed to the public internet or local networks. The campaign leverages CVE-2026-39364, a high-severity vulnerability (CVSS 8.2) that allows unauthenticated attackers to bypass 'server.fs.deny' restrictions. By appending specific query parameters (?raw, ?import&raw, or ?import&url&inline) to requests directed at the /@fs/ endpoint, attackers can trick the server into returning the contents of files that should be protected. 

The attackers specifically target sensitive files including AWS and Azure credentials, infrastructure state files (terraform.tfstate), serverless configurations, and system files like /etc/passwd or .env files. The campaign utilizes cloud provider IP ranges and spoofed User-Agent strings (mimicking popular crawlers like Googlebot and ClaudeBot) to evade detection and circumvent IP-based access control lists. This activity poses a critical risk to organizations that have misconfigured development environments, potentially leading to full cloud administrative compromise.

## Attack Chain

1. Attacker performs mass scanning to identify Vite development servers exposed via the --host flag or Docker misconfiguration.
2. Attacker sends HTTP GET requests to the /@fs/ endpoint of the target Vite server.
3. Attacker appends malicious query parameters (?raw, ?import&raw, or ?import&url&inline) to the URI to bypass the server.fs.deny logic.
4. Attacker includes forged 'X-Forwarded-For' and 'X-Real-IP' headers to bypass potential IP-based filtering or rate-limiting.
5. Attacker impersonates legitimate search engines or AI bots via 'User-Agent' headers to avoid automated security alerts.
6. The Vite server processes the request, ignores the deny list due to the bypass, and returns the contents of the target sensitive file in the HTTP response body.
7. Attacker parses the plaintext response to extract API secrets, cloud credentials, and deployment environment variables for further access.

## Impact

Successful exploitation allows attackers to gain unauthorized access to cloud environments, internal configuration, and secrets. This has resulted in the theft of AWS credentials, Azure profiles, and infrastructure state files. The wide-scale nature of the campaign affects any organization using misconfigured Vite development servers, with observed activity originating from multiple global regions. Failure to mitigate this vulnerability risks complete lateral movement and compromise of production cloud infrastructure.

## Recommendation

Prioritize auditing all Vite development deployments to ensure they are not exposed to the internet. 

* Immediately restrict Vite development server access to 'localhost' (default) and verify that no '--host' or 'server.host' flags are used in public-facing or non-secured environments.
* Deploy the webserver-based Sigma rule provided in this brief to detect the specific query parameter bypass attempts on the /@fs/ endpoint.
* Monitor proxy and web server logs for requests containing suspicious query parameters (?raw, ?import&raw) combined with spoofed crawlers in the User-Agent field.
* Revoke and rotate any credentials or secrets found on servers where Vite was exposed to the network.
