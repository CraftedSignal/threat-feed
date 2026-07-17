---
title: IBM PowerVM Novalink Vulnerable to Denial of Service via Specially-Crafted Request
slug: 2026-07-ibm-powervm-dos
description: IBM PowerVM Novalink is vulnerable to CVE-2026-9171, a denial-of-service attack where a remote unauthenticated attacker can send a specially-crafted request to cause the server to consume excessive memory resources, leading to system unavailability.
date: "2026-07-17T19:20:41Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - IBM
  - PowerVM Novalink
vendors:
  - IBM
products:
  - PowerVM Novalink 2.2.02.2.12.2.1.1
  - PowerVM Novalink 2.3.02.3.0.12.3.12.3.2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Exploitation for Denial of Service
    evidence: A remote attacker could exploit this vulnerability to cause the server to consume memory resources.
    confidence_band: high
cves:
  - id: CVE-2026-9171
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9171
  - https://www.ibm.com/support/pages/node/7280226
iocs:
  - type: url
    value: https://www.ibm.com/support/pages/node/7280226
ioc_counts:
  url: 1
---

IBM PowerVM Novalink is affected by a high-severity denial-of-service vulnerability, identified as CVE-2026-9171. This flaw allows a remote attacker, without authentication, to exploit the system by sending a specially-crafted network request. Upon receiving this malicious request, the PowerVM Novalink server is compelled to consume an excessive amount of its memory resources. This uncontrolled resource consumption, classified under CWE-400, leads to a denial-of-service condition, making the affected system unresponsive and unavailable to legitimate users and processes. The vulnerability impacts specific versions of PowerVM Novalink, including 2.2.02.2.12.2.1.1 and 2.3.02.3.0.12.3.12.3.2. Organizations using these versions are at risk of service disruption if targeted.

## Impact

Successful exploitation of CVE-2026-9171 results in a denial-of-service (DoS) condition for IBM PowerVM Novalink systems. Attackers can leverage this vulnerability to force the server into consuming all available memory, causing it to become unresponsive or crash. This leads to severe operational disruption, as the affected systems will be unable to perform their intended functions, thereby impacting critical business processes dependent on Novalink. There is no observed compromise of confidentiality or integrity associated with this specific vulnerability, but the loss of availability can have significant financial and operational consequences for affected organizations.

## Recommendation

* Consult the IBM support page for CVE-2026-9171 at `https://www.ibm.com/support/pages/node/7280226` for official patches or mitigation strategies immediately.
* Patch CVE-2026-9171 on all affected IBM PowerVM Novalink instances to prevent remote denial-of-service attacks.
