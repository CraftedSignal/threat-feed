---
title: XXE Injection Vulnerability in IBM QRadar
slug: 2026-08-ibm-qradar-xxe
description: IBM QRadar contains an XML External Entity (XXE) injection vulnerability in the event processing pipeline that allows unauthenticated attackers to read arbitrary files from the system.
date: "2026-08-05T17:20:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cve-2026-10025
  - xxe
  - siem
vendors:
  - IBM
products:
  - QRadar
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The system processes XML-formatted syslog events sent to port 514 (UDP/TCP) without authentication.
    confidence_band: high
cves:
  - id: CVE-2026-10025
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10025
  - https://www.ibm.com/support/pages/node/7282394
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IBM QRadar systems to the versions specified in IBM advisory node 7282394
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-10025 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Disable XML-format property autodetection on log source configurations if not currently in use
      owner: IT Operations
      addresses: CVE-2026-10025
      evidence: Vulnerability requires XML-format property autodetection to be enabled
---

IBM QRadar versions 7.6.0.0 through 7.6.0.1 and 7.5.0 through 7.5.0 UP 15 Interim Fix 005 are susceptible to an XML External Entity (XXE) injection vulnerability. The flaw exists within the `parseXmlPayload()` function located in the `q1labs_core.jar` component of the event processing pipeline. This vulnerability is reachable when the QRadar system has at least one log source type configured to utilize XML-format property autodetection. An unauthenticated attacker can trigger this vulnerability by transmitting specially crafted XML-formatted syslog events to the standard syslog ingestion ports (UDP/TCP 514). Exploitation of this vulnerability allows for unauthorized access to local files on the system, potentially exposing sensitive configuration data or credentials stored within the QRadar environment.

## Impact

Successful exploitation of this XXE vulnerability results in unauthorized disclosure of information (Confidentiality impact) and potentially impacts system availability (Availability impact) by disrupting the event processing pipeline. Organizations running affected versions of IBM QRadar and leveraging XML-based syslog ingestion are at risk of local file disclosure. Given the centralized nature of QRadar as a SIEM, the exposure of files could lead to a broader compromise of the monitored environment.

## Recommendation

- Identify all QRadar instances running versions 7.6.0.0-7.6.0.1 or 7.5.0 (up to UP 15 Interim Fix 005).
- Apply the vendor-provided security patches from IBM for CVE-2026-10025 immediately.
- Review log source configurations to disable XML-format property autodetection if it is not strictly required for business operations.
- Monitor network traffic for unusual or highly anomalous XML-formatted syslog patterns directed at port 514 from untrusted segments.
