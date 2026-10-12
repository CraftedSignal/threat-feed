---
title: Detection of Authentication Certificate Theft or Forgery
slug: 2026-10-steal-or-forge-auth-certs
description: This correlation identifies anomalous activity targeting Windows Certificate Services by aggregating multiple risk-based detections on a single system, signaling potential adversary efforts to forge or steal authentication certificates.
date: "2026-10-12T17:58:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - certificate-theft
  - identity-compromise
  - adcs
  - credential-access
vendors:
  - Microsoft
products:
  - Active Directory Certificate Services
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
    evidence: The analytic identifies potential threats related to the theft or forgery of authentication certificates.
    confidence_band: high
references:
  - https://research.splunk.com/stories/windows_certificate_services/
  - https://attack.mitre.org/techniques/T1649/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable and audit the Windows Certificate Services analytic story.
      owner: Detection Engineering
      due: 48h
      evidence: Source instructs to ensure the analytic story is enabled and requires data logging.
  hunt_leads:
    - lead: Identify systems showing multiple alerts within the Windows Certificate Services analytic story.
      technique_id: T1649
      data_needed:
        - Risk data model events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Correlation logic requires 5+ events to trigger.
---

This threat brief focuses on the identification of adversary behavior targeting Active Directory Certificate Services (AD CS). By monitoring for the theft or forgery of authentication certificates, security teams can detect attempts to compromise core identity and authentication infrastructure. The methodology relies on aggregating risk signals from the "Windows Certificate Services" analytic story. When an endpoint generates five or more distinct security events related to certificate manipulation within a set timeframe, it indicates a high-probability attempt to bypass authentication controls. Such activity is a precursor to lateral movement, privilege escalation, or persistence, enabling attackers to gain unauthorized access to sensitive systems or impersonate privileged users.

## Impact

Successful exploitation of authentication certificate infrastructure allows adversaries to maintain persistent, high-privileged access to a Windows domain. By forging certificates or stealing existing ones, an attacker can bypass traditional credential-based authentication, making their presence difficult to detect via standard identity monitoring. If this activity is confirmed as malicious, it represents a severe security breach that may necessitate a full recovery of the environment's identity and trust infrastructure.

## Recommendation

Prioritize the investigation of systems identified by the aggregation of risk signals related to the "Windows Certificate Services" story.
- Ensure all individual analytic rules within the Windows Certificate Services story are enabled and correctly tuned to reduce baseline noise.
- Review telemetry from Windows Event Logs, specifically focusing on certificate request and issuance events on Active Directory Certificate Services servers.
- Use the risk-based drilldown provided by your SIEM to examine the specific sequence of alerts triggered on the flagged risk object.
- Investigate the processes and users associated with the identified certificate manipulation to determine if the activity is authorized administrative maintenance or a potential security compromise.
