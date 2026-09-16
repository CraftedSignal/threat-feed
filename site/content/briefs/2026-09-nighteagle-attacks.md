---
title: NightEagle APT Targets Russian Organizations with GhostContainer Backdoor
slug: 2026-09-nighteagle-attacks
description: The NightEagle APT group is actively targeting organizations by exploiting compromised VPN credentials, deploying the memory-resident GhostContainer backdoor on Exchange servers, and utilizing legitimate tunneling tools for lateral movement.
date: "2026-09-16T13:12:31Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - NightEagle
cpes:
  - cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2010:sp3_rollup_30:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_23:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_14:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_15:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_3:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_4:*:*:*:*:*:*
tags:
  - nighteagle
  - apt
  - exchange
  - backdoor
  - tunnel
vendors:
  - Microsoft
products:
  - Exchange Server
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078.001
    technique_name: 'Valid Accounts: Default Accounts'
    evidence: In most incidents, the attackers used compromised valid credentials to gain access to corporate VPNs.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The Stub class processes C2 commands delivered to the infected system through the x-owa-urlpostdata headers.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.001
    technique_name: Remote Desktop Protocol
    evidence: Once the attackers gain sufficient privileges during an attack, they leverage RDP to move laterally within the internal network segment.
    confidence_band: high
cves:
  - id: CVE-2020-0688
    cvss: 8.8
    epss: 0.99965
references:
  - https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit VPN logs for anomalous source IP addresses or irregular connection times.
      owner: SOC
      due: 24h
      evidence: Attackers used compromised valid credentials to gain access to corporate VPNs.
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2020-0688 on all Exchange servers.
      owner: IT Operations
      addresses: CVE-2020-0688
      evidence: The backdoor incorporates components from several open-source projects, including the Neo-reGeorg tunnel, an exploit for the CVE-2020-0688 vulnerability.
---

The NightEagle APT group (also known as APT-Q-95) has expanded its targeting to include organizations in Russia. Active since 2023, the group employs a sophisticated multi-stage approach, initiating access via compromised VPN credentials. A primary focus of their campaign is the deployment of the GhostContainer backdoor on Microsoft Exchange servers. This backdoor is highly evasive, functioning in-memory by patching amsi.dll and ntdll.dll to circumvent security monitoring. The attackers utilize custom C2 communication headers and frequently abuse legitimate utilities, such as Microsoft Dev Tunnels, to facilitate RDP-based lateral movement. Tools are sourced from GitHub repositories disguised to mimic legitimate software, while the payload delivery often involves sophisticated manipulation of ASP.NET VIEWSTATE parameters. The group’s reliance on dual-use infrastructure and legitimate tunneling services poses significant challenges for traditional perimeter-based defenses.

## Attack Chain

1. Initial access is gained by using compromised valid credentials to authenticate against corporate VPN services.
2. Attackers extract cryptographic keys from the ASP.NET configuration on Microsoft Exchange servers.
3. The VIEWSTATE framework parameter is overwritten to inject a payload, facilitating the in-memory execution of the GhostContainer backdoor.
4. The backdoor establishes persistence in-memory and patches amsi.dll and ntdll.dll to bypass AMSI and Windows Event Log monitoring.
5. Command-and-control communication is established by parsing specific headers (x-owa-urlpostdata) on the infected Exchange host.
6. Attackers download malicious toolsets from GitHub repositories, disguised as legitimate software archives (e.g., Adobe or 1C broker software).
7. Microsoft Dev Tunnels are configured on the compromised system to expose RDP (port 3389) to the internet.
8. Attackers perform lateral movement throughout the internal network using the established RDP tunnel.

## Impact

The campaign results in persistent unauthorized access to internal network segments and sensitive Microsoft Exchange environments. By gaining RDP-level access to internal workstations and servers, NightEagle can facilitate data exfiltration, credential harvesting, and long-term surveillance within targeted Russian businesses.

## Recommendation

Prioritize the identification of abnormal RDP tunneling and suspicious memory-injected payloads on Exchange infrastructure.
- Patch CVE-2020-0688 on all Microsoft Exchange servers immediately.
- Hunt for the execution of unauthorized binaries masquerading as legitimate software (e.g., AdobeSync.exe, 1cbroker.exe) originating from unauthorized paths.
- Monitor for the creation of Microsoft Dev Tunnels sessions, specifically connections to *.devtunnels.ms.
- Restrict and audit the use of VPN credentials, implementing phishing-resistant MFA for all remote access.
- Baseline and monitor ASP.NET configuration changes on web servers to detect potential tampering with VIEWSTATE parameters.
