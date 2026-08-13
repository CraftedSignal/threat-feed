---
title: IBM i Remote Denial-of-Service via Buffer Overflow (CVE-2026-18846)
slug: 2026-08-ibm-i-buffer-overflow
description: IBM i versions 7.3 through 7.6 are susceptible to a buffer overflow vulnerability allowing unauthenticated remote attackers to trigger a denial-of-service condition via malformed requests.
date: "2026-08-13T22:08:00Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - IBM
products:
  - i
cves:
  - id: CVE-2026-18846
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18846
  - https://www.ibm.com/support/pages/node/7283578
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected IBM i systems (7.3-7.6) using the vendor-supplied fix.
      owner: IT Operations
      due: 48h
      evidence: IBM security advisory node 7283578
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to IBM i host servers to known, trusted subnets.
      owner: IT Operations
      addresses: CVE-2026-18846
      evidence: NVD vulnerability description
---

IBM has disclosed a security vulnerability identified as CVE-2026-18846 affecting the IBM i operating system, specifically versions 7.3, 7.4, 7.5, and 7.6. The issue arises from improper validation of client data processed by host servers running on the platform, which can lead to an out-of-bounds write (CWE-787). A remote, unauthenticated attacker can exploit this weakness by sending specially crafted, malformed requests to these host servers. Successful exploitation results in a buffer overflow that forces the affected server component to crash, causing a denial-of-service (DoS) condition. Given the criticality of the IBM i platform in enterprise environments, this vulnerability poses a significant availability risk if left unpatched.

## Impact

Successful exploitation of this vulnerability leads to the crash of host server processes on the IBM i platform, resulting in an immediate denial-of-service for connected users and dependent applications. This vulnerability carries a CVSS 3.1 base score of 7.5 (High) and is considered automatable by CISA. Organizations relying on IBM i for critical business operations may face significant service disruptions if malicious actors leverage this flaw to destabilize system availability.

## Recommendation

* Apply the official security patches provided by IBM as documented in the support advisory (https://www.ibm.com/support/pages/node/7283578) immediately.
* Implement network-level access controls to restrict exposure of IBM i host server ports to trusted IP ranges only, mitigating the ability for unauthorized remote attackers to reach the vulnerable services.
* Audit firewall configurations to ensure that IBM i host server traffic is not directly reachable from untrusted or public networks.
