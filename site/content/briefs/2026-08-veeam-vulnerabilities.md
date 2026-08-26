---
title: Multiple Critical Vulnerabilities in Veeam Backup and ONE Products
slug: 2026-08-veeam-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-58070 and CVE-2026-65641, affect Veeam Backup & Replication and Veeam ONE, potentially allowing unauthorized access to sensitive backup data and security policy bypass.
date: "2026-08-26T13:58:31Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Veeam
products:
  - Veeam Backup & Replication (13.x)
  - Veeam ONE (13.x)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1080/
  - https://www.veeam.com/kb4902
  - https://www.veeam.com/kb4905
  - https://www.cve.org/CVERecord?id=CVE-2026-58070
  - https://www.cve.org/CVERecord?id=CVE-2026-65641
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Veeam Backup & Replication and Veeam ONE instances to latest version
      owner: IT Operations
      due: 24h
      evidence: Veeam KB4902 and KB4905
---

On August 25, 2026, Veeam released security updates to address multiple vulnerabilities affecting Veeam Backup & Replication and Veeam ONE. The vulnerabilities identified as CVE-2026-58070 and CVE-2026-65641 impact Veeam Backup & Replication versions 13.x prior to 13.0.3 and Veeam ONE versions 13.x prior to 13.0.2 Patch 1. These security flaws present a significant risk as they could allow an unauthorized attacker to circumvent established security policies and compromise the confidentiality of sensitive enterprise backup data. Given the central role these products play in disaster recovery and data storage, immediate patching of all internet-facing or reachable instances is critical to prevent exploitation of the management interfaces.

## Impact

Successful exploitation of these vulnerabilities can lead to unauthorized access to backups, potentially resulting in the exfiltration of sensitive organizational data or the destruction of backup sets, which would hinder recovery efforts during a ransomware event. Organizations utilizing these Veeam products must prioritize the application of the vendor-provided patches listed in KB4902 and KB4905.

## Recommendation

- Immediately update Veeam Backup & Replication to version 13.0.3 and Veeam ONE to version 13.0.2 Patch 1 as documented in vendor KBs 4902 and 4905.
- Review access logs for the Veeam management console to identify unauthorized access attempts or unusual API calls, particularly from non-standard IP ranges.
- Isolate Veeam management interfaces from public network exposure.
- Monitor for service-specific errors or unexpected process behavior on the servers hosting Veeam infrastructure components.
