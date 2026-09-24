---
title: Active Exploitation of Code Injection Vulnerability in Microsoft SharePoint Server
slug: 2026-09-sharepoint-rce
description: Authenticated attackers are actively exploiting CVE-2026-65660, a code injection vulnerability in Microsoft SharePoint Server, to execute arbitrary code, with potential for pre-authentication RCE when chained with other flaws.
date: "2026-09-24T19:51:47Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:subscription:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:subscription:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:enterprise:*:*:*
tags:
  - vulnerability
  - rce
  - exploitation
  - sharepoint
vendors:
  - Microsoft
products:
  - SharePoint Enterprise Server 2016 (< 16.0.5565.1001)
  - SharePoint Server 2019 (< 16.0.10417.20198)
  - SharePoint Server Subscription Edition (< 16.0.19725.20522)
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Chained with other SharePoint vulnerabilities, this vulnerability can achieve pre-authentication remote code execution on SharePoint servers configured to permit anonymous access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: Monitor for indicators of compromise and exploitation activity, including... evidence of deserialization attacks, web shell deployment, or malicious process execution
    confidence_band: high
cves:
  - id: CVE-2026-65660
    cvss: 8.8
    epss: 0.00807
references:
  - https://cyber.gc.ca/en/alerts-advisories/al26-023-vulnerability-impacting-microsoft-sharepoint-server-cve-2026-65660
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65660
  - https://www.cve.org/CVERecord?id=CVE-2026-65660
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade SharePoint instances to fixed versions specified in the brief
      owner: IT Operations
      due: 24h
      evidence: Suggested actions table in the advisory
    - action: Restrict external access to management interfaces
      owner: SOC
      due: 24h
      evidence: Reduce the attack surface by restricting or eliminating direct internet exposure
  hunt_leads:
    - lead: Look for IIS machine key access or unusual web part configurations
      technique_id: T1505.003
      data_needed:
        - IIS logs
        - SharePoint Audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Monitor for indicators... suspicious access to IIS machine keys
  mitigation_plan:
    - priority: immediate
      action: Enable AMSI integration and set Request Body Scan Mode to Full
      owner: IT Operations
      addresses: CVE-2026-65660
      evidence: Harden SharePoint deployments by enabling Antimalware Scan Interface (AMSI) integration
---

The Canadian Centre for Cyber Security has confirmed active exploitation of CVE-2026-65660, a code injection vulnerability (CWE-94) affecting Microsoft SharePoint Server. The flaw permits an authenticated attacker to achieve arbitrary code execution on vulnerable instances. Crucially, when chained with other SharePoint vulnerabilities, attackers can reach pre-authentication remote code execution (RCE) on servers that allow anonymous access. This poses a severe risk to organizations running legacy or unpatched SharePoint deployments. Microsoft SharePoint Enterprise Server 2016 and Server 2019 reached end-of-life on July 15, 2026, and remain highly susceptible. Defenders must prioritize upgrading to the specified fixed versions to remediate the vulnerability and mitigate the risk of ongoing exploitation.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Microsoft SharePoint instances.
2. If anonymous access is enabled, the attacker chains existing auxiliary vulnerabilities to bypass initial authentication.
3. Attacker targets the specific code injection vector defined by CVE-2026-65660.
4. The malicious request triggers the underlying vulnerability, allowing for code execution within the SharePoint application context.
5. Attacker executes arbitrary commands, potentially deploying a web shell to maintain persistence (e.g., via T1505.003).
6. Attacker leverages the elevated application context to perform further privilege escalation or move laterally within the server environment.
7. Attacker achieves the final objective, which may include data exfiltration or internal network reconnaissance.

## Impact

Successful exploitation allows attackers to gain full code execution on affected SharePoint servers. This can lead to total system compromise, unauthorized access to sensitive internal data, and the establishment of persistent backdoors within the organization's network. Given that many SharePoint instances store critical business and enterprise data, the impact of a successful breach is significant. Organizations running EOL versions (2016 and 2019) are at a particularly elevated risk, as they no longer receive standard support and may lack defense-in-depth protections.

## Recommendation

Prioritize the immediate upgrade of all SharePoint instances to the fixed versions listed below. Enable Antimalware Scan Interface (AMSI) integration for SharePoint web applications and set the scan mode to 'Full' to improve detection of malicious payloads. Restrict access to management interfaces like SharePoint Central Administration and ensure all internet-facing instances are shielded from unnecessary exposure. Monitor IIS and SharePoint logs for anomalous administrative behavior, unauthorized web part modifications, and unexpected deserialization activity that may signal exploitation.
