---
title: Multiple Vulnerabilities in Erlang/OTP
slug: 2026-09-erlang-otp-vulnerabilities
description: Erlang/OTP contains multiple vulnerabilities, including CVE-2024-48337, CVE-2024-48338, and CVE-2024-48339, which may allow attackers to trigger Denial of Service, bypass security controls, or facilitate data disclosure.
date: "2026-09-22T13:54:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - erlang
  - dos
vendors:
  - Erlang Solutions
products:
  - Erlang/OTP
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3499
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Identify Erlang/OTP installations and upgrade to the version containing patches for CVE-2024-48337, CVE-2024-48338, and CVE-2024-48339.
      owner: IT Operations
      addresses: CVE-2024-48337, CVE-2024-48338, CVE-2024-48339
      evidence: BSI security advisory reporting vulnerabilities in Erlang/OTP.
---

The BSI (German Federal Office for Information Security) has reported multiple security vulnerabilities affecting Erlang/OTP. These vulnerabilities, identified as CVE-2024-48337, CVE-2024-48338, and CVE-2024-48339, expose systems running Erlang/OTP to significant risks. An unauthenticated or remote attacker can potentially leverage these flaws to conduct Denial of Service (DoS) attacks, circumvent implemented security mechanisms, or gain unauthorized access to sensitive data via manipulation or disclosure. These vulnerabilities impact the core Erlang runtime environment, necessitating immediate review of existing Erlang/OTP deployments across Windows, Linux, and macOS environments. Organizations utilizing Erlang-based applications should verify their current versioning against the Erlang/OTP security advisory and apply the necessary patches provided by Erlang Solutions to remediate these exposures.

## Impact

Successful exploitation of these vulnerabilities could result in service instability through DoS, loss of confidentiality via unauthorized data disclosure, and loss of integrity through unauthorized data manipulation. These risks are heightened in distributed systems and backend services that rely on Erlang/OTP for high-concurrency processing, potentially impacting business operations and critical application availability.

## Recommendation

Prioritize the identification of all servers and applications utilizing Erlang/OTP within the infrastructure. Review the Erlang Solutions official security documentation to determine the specific versions affected by CVE-2024-48337, CVE-2024-48338, and CVE-2024-48339. Plan and execute an emergency update cycle to patch the Erlang/OTP runtime to the latest secure version for all internet-facing or high-value internal systems.
