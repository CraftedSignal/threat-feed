---
title: Budibase SSRF Vulnerability in AI Extract File Automation Step
slug: 2026-05-budibase-ssrf
description: Budibase is vulnerable to server-side request forgery (SSRF) due to a missing IP blacklist validation (CVE-2026-45548) in the AI Extract File automation step, potentially allowing an authenticated user with builder permissions to access internal resources and cloud metadata.
date: "2026-05-15T17:48:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - budibase
  - cloud
vendors:
  - Budibase
products:
  - '@budibase/server (< 3.34.8)'
  - Budibase Cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-rpj4-7x2v-wjrf
  - CVE-2026-45548
iocs:
  - type: url
    value: http://169.254.169.254/latest/meta-data/
ioc_counts:
  url: 1
rules:
  - title: Detect Budibase SSRF Attempt via AI Extract File
    description: Detects CVE-2026-45548 exploitation — outbound connection from Budibase server to private IP ranges indicating a potential SSRF attempt via the AI Extract File automation step.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Budibase API Automation Creation with SSRF Payload
    description: Detects attempts to create Budibase automations via the API with a SSRF payload in the 'fileUrl' field, indicative of CVE-2026-45548 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Budibase is vulnerable to a Server-Side Request Forgery (SSRF) vulnerability in the AI Extract File automation step. This vulnerability (CVE-2026-45548) exists because the `processUrlFile` function in `packages/server/src/automations/steps/ai/extract.ts` lacks the IP blacklist validation that is applied to all other automation steps. An authenticated user with builder permissions can exploit this vulnerability to make requests to internal network addresses. This oversight allows attackers to bypass intended security controls and potentially access sensitive information or resources within the internal network or cloud environment. This vulnerability affects @budibase/server versions prior to 3.34.8.

## Attack Chain

1.  Attacker logs into a Budibase instance as an authenticated user with builder permissions.
2.  The attacker creates or opens an existing application within Budibase.
3.  The attacker navigates to the Automations section and initiates a "New Automation."
4.  An "App Action" trigger is added to start the automation workflow.
5.  An "AI > Extract File Data" step is added to the automation workflow.
6.  The attacker configures the "Source" as "URL" and sets the "File URL" to an internal IP address (e.g., `http://169.254.169.254/latest/meta-data/`).
7.  The attacker executes the automation by clicking "Run Test," triggering the `processUrlFile` function.
8.  Due to the missing IP blacklist validation, the server makes an outbound HTTP request to the specified internal IP address, potentially exposing internal resources or cloud metadata.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-45548) can lead to several critical impacts. An attacker can access cloud metadata endpoints, potentially exposing sensitive information such as AWS IAM credentials, GCP service tokens, or Azure IMDS. The attacker can also scan internal network services and ports to discover vulnerable or misconfigured services. Access to internal APIs not intended for external access is also possible, potentially allowing the attacker to perform unauthorized actions. Furthermore, the attacker can exfiltrate data from internal services via the automation response. In the context of Budibase Cloud (SaaS), this could be leveraged to steal cloud provider credentials, leading to full infrastructure compromise.

## Recommendation

*   Upgrade @budibase/server to version 3.34.8 or later to patch CVE-2026-45548, addressing the missing IP blacklist validation in the AI Extract File automation step.
*   Deploy the Sigma rule "Detect Budibase SSRF Attempt via AI Extract File" to identify potential exploitation attempts by monitoring for outbound connections from the Budibase server to private IP ranges.
*   Review and restrict network access controls to internal resources to minimize the impact of potential SSRF attacks, limiting the exposure of sensitive services and data.
