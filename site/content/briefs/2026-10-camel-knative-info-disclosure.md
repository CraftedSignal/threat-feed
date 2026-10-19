---
title: Information Disclosure in Apache Camel Knative HTTP Consumer
slug: 2026-10-camel-knative-info-disclosure
description: An information disclosure vulnerability (CVE-2026-84180) in the camel-knative HTTP consumer allows remote attackers to retrieve internal application details, stack traces, and configuration data via intentional route failures.
date: "2026-10-19T12:17:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - camel
  - information-disclosure
  - cloud-native
  - cve-2026-84180
vendors:
  - Apache
products:
  - camel-knative (4.0.0-4.18.4, 4.19.0-4.22.0)
  - camel-quarkus (prior to 3.40.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote caller provokes a route failure on the consumer side and reads the exception detail from the response body.
    confidence_band: high
cves:
  - id: CVE-2026-84180
    cvss: 5.3
references:
  - https://camel.apache.org/security/CVE-2026-84180.html
  - https://issues.apache.org/jira/browse/CAMEL-24428
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Apache Camel to version 4.18.5, 4.22.1, or 4.23.0
      owner: IT Operations
      due: 72h
      evidence: Vendor security advisory for CVE-2026-84180
  mitigation_plan:
    - priority: immediate
      action: Configure muteException=true on camel-knative consumers
      owner: IT Operations
      addresses: CVE-2026-84180
      evidence: Official fix documentation
---

Apache Camel contains an information disclosure vulnerability in the `camel-knative` component, tracked as CVE-2026-84180. When a Knative HTTP consumer route encounters an internal processing error, the application fails to handle the exception safely. Instead of suppressing the output, the component serializes the exception class name, the error message, and the full stack trace into the HTTP response body returned to the caller. 

This issue is significant because it allows remote, unauthenticated attackers to probe the internal structure of the deployment. By sending crafted CloudEvents that intentionally trigger failures, an attacker can extract sensitive metadata including internal hostnames, filesystem structures, package names, and potentially embedded connection strings or configuration data. This vulnerability affects multiple versions of Camel (4.0.0 through 4.18.4, and 4.19.0 through 4.22.0). The fix introduces a `muteException` option, which defaults to true, ensuring that error status codes are returned without leaking exception details.

## Impact

Successful exploitation results in the leakage of sensitive internal application telemetry and environmental configuration. This data can be leveraged to map internal network segments, identify vulnerable downstream services, or harvest credentials/connection strings if these are included in exception messages, facilitating subsequent, more targeted attacks against the organization's infrastructure.

## Recommendation

Prioritize the upgrade of affected Apache Camel deployments to the patched versions.

* Upgrade Apache Camel to 4.18.5, 4.22.1, or 4.23.0 to resolve CVE-2026-84180.
* For Camel Quarkus users, ensure the project is updated to Quarkus 3.40.0 or later, which incorporates the fixed Camel 4.22.1 library.
* If patching is not immediately feasible, implement an `onException` handler within all consumer routes that explicitly catches potential failures and masks the response body before it is transmitted to the caller.
* Enable the `muteException` setting within the `camel-knative` configuration to prevent stack traces from being written to HTTP response bodies.
