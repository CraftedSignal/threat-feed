---
title: Critical OS Command Injection in IBM Hardware Management Console
slug: 2026-07-ibm-hmc-rce
description: A critical unauthenticated command injection vulnerability (CVE-2026-12943) in IBM HMC and Novalink allows remote attackers to execute arbitrary commands with elevated privileges.
date: "2026-07-30T19:30:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - ibm-power
  - critical
vendors:
  - IBM
products:
  - HMC V10.3
  - HMC V11.1
  - Novalink
cves:
  - id: CVE-2026-12943
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12943
  - https://www.ibm.com/support/pages/node/7278667
---

IBM has identified a critical OS command injection vulnerability, tracked as CVE-2026-12943, affecting various versions of the Hardware Management Console (HMC) and Novalink management software used in IBM Power environments. The vulnerability originates from improper validation of user-supplied input, which can be leveraged by an unauthenticated attacker to execute arbitrary commands with root or elevated system privileges. This flaw, rated with a CVSS v3.1 base score of 9.8, represents a significant security risk for data center infrastructure management, as it permits full system compromise without prior authentication. Organizations utilizing the affected HMC V10.3 and V11.1 release branches should prioritize patching as immediate remediation.

## Impact

Successful exploitation of this vulnerability results in full system compromise of the IBM HMC or Novalink appliance. Because the HMC serves as the central control point for IBM Power server virtualization and partitioning, an attacker gaining elevated execution capabilities can manipulate LPAR (Logical Partition) configurations, access sensitive system data, disrupt operations, or utilize the appliance as a pivot point for lateral movement within the management network. Given the critical nature of these appliances in enterprise infrastructure, the potential for widespread disruption is high.

## Recommendation

Prioritize the immediate application of security patches provided by IBM for affected HMC and Novalink versions. Refer to the official IBM advisory (https://www.ibm.com/support/pages/node/7278667) to identify the specific maintenance level required for your HMC deployment. For organizations unable to patch immediately, restrict network access to the HMC/Novalink management interface to trusted administrative IP ranges only, using network-layer access control lists (ACLs).
