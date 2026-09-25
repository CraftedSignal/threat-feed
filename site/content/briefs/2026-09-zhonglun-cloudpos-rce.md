---
title: Remote Code Injection Vulnerability in Zhonglun CloudPos
slug: 2026-09-zhonglun-cloudpos-rce
description: A code injection vulnerability in the JSBridge component of Zhonglun CloudPos (up to 3.0.1.76) allows remote attackers to execute arbitrary code via the OpenLocalBrowser function.
date: "2026-09-25T18:54:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zhonglun:cloudpos:*:*:*:*:*:*:*:*
tags:
  - code-injection
  - vulnerability
  - cve-2026-97871
vendors:
  - Zhonglun
products:
  - CloudPos (<= 3.0.1.76)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-97871
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97871
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Isolate CloudPos instances from internet exposure due to lack of vendor patch.
      owner: IT Operations
      addresses: CVE-2026-97871
      evidence: The exploit has been disclosed to the public and may be used.
---

Zhonglun CloudPos versions up to 3.0.1.76 are vulnerable to a remote code injection flaw located within the JSBridge component. Specifically, the vulnerability exists in the OpenLocalBrowser function found in the file ZlPos/ZlPos/Bizlogic/JSBridge.cs. Attackers can manipulate the url argument processed by this function to achieve remote code execution on affected systems. The vulnerability was publicly disclosed, and there is no evidence that the vendor has addressed the issue or provided a security update. Given the remote exploitability and the lack of vendor response, organizations utilizing this software are at significant risk of unauthorized access and system compromise.

## Impact

Successful exploitation allows for unauthenticated remote code execution, which could lead to full system compromise, data exfiltration, or the deployment of additional malicious payloads on POS systems. There are no available patches, and the vendor has remained unresponsive to the vulnerability disclosure.

## Recommendation

1. Inventory all instances of Zhonglun CloudPos within the environment and evaluate exposure to internet-facing networks.
2. Restrict network access to CloudPos instances to known, trusted management segments until a security patch is provided by the vendor.
3. Monitor endpoint logs for suspicious process spawning from the CloudPos application process, particularly any attempts to launch browsers or shell commands originating from JSBridge-related functions.
