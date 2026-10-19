---
title: SSRF Vulnerability in CrewAI SeleniumScrapingTool (CVE-2026-112308)
slug: 2026-10-crewai-ssrf
description: An SSRF vulnerability in the SeleniumScrapingTool component of crewai-tools allows attackers to exfiltrate internal resources or cloud credentials via malicious prompt injection.
date: "2026-10-19T18:08:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:crewai:crewai-tools:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - prompt-injection
  - cloud-security
vendors:
  - CrewAI
products:
  - crewai-tools (<= 1.15.28)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers influencing agent tool input through prompt injection can direct headless Chrome to loopback, RFC1918, or cloud metadata addresses to disclose internal data and cloud credentials.
    confidence_band: high
cves:
  - id: CVE-2026-112308
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112308
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade crewai-tools to version 1.15.29 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-112308 remediation
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering for 169.254.169.254 and private IP blocks on host infrastructure.
      owner: IT Operations
      addresses: CVE-2026-112308
      evidence: Vulnerability remediation
---

CrewAI crewai-tools versions 1.15.28 and earlier are affected by a server-side request forgery (SSRF) vulnerability located in the SeleniumScrapingTool component. The tool fails to implement necessary URL validation via the validate_url function, leaving the service open to requests targeting internal infrastructure. An attacker can exploit this via prompt injection by providing a crafted URL to an AI agent that utilizes the SeleniumScrapingTool. This enables the headless Chrome instance controlled by the tool to perform requests against the local loopback interface, private RFC1918 network segments, or cloud metadata endpoints. Successful exploitation allows for the unauthorized disclosure of internal data, configuration files, or cloud environment credentials, significantly impacting the confidentiality of the target environment.

## Impact

The vulnerability affects organizations deploying crewai-tools within their production environments, particularly those integrated with cloud services where metadata endpoints (e.g., 169.254.169.254) are accessible. Unauthorized access to these endpoints can lead to the full compromise of identity and access management (IAM) credentials associated with the hosting instance or container, potentially escalating access to broader cloud infrastructure.

## Recommendation

- Update crewai-tools to version 1.15.29 or later immediately to incorporate the missing URL validation logic.
- Implement network egress filtering on instances running AI agent tools to block requests to non-routable internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and cloud metadata services (169.254.169.254).
- Restrict the permissions of the IAM roles assigned to machines running these tools to follow the principle of least privilege, preventing unauthorized access to sensitive data even if a credential exfiltration attempt occurs.
- Audit logs for the headless browser process execution to identify anomalous request patterns directed at internal resources.
