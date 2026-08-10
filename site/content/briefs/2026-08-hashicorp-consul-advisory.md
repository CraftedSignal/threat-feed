---
title: Security Updates for HashiCorp Consul
slug: 2026-08-hashicorp-consul-advisory
description: HashiCorp has released security advisory HCSEC-2026-25 addressing multiple vulnerabilities in Consul Community Edition and Consul Enterprise that require immediate patching.
date: "2026-08-10T19:30:32Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - informational
  - product-news
vendors:
  - HashiCorp
products:
  - Consul Community Edition
  - Consul Enterprise
references:
  - https://cyber.gc.ca/en/alerts-advisories/hashicorp-security-advisory-av26-791
  - https://discuss.hashicorp.com/t/hcsec-2026-25-multiple-vulnerabilities-impacting-hashicorp-consul/77629
iocs:
  - type: url
    value: https://discuss.hashicorp.com/t/hcsec-2026-25-multiple-vulnerabilities-impacting-hashicorp-consul/77629
ioc_counts:
  url: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Consul Community Edition and Consul Enterprise to the specified patched versions.
      owner: IT Operations
      addresses: Consul vulnerabilities
      evidence: HashiCorp Security Advisory HCSEC-2026-25
---

HashiCorp has issued a security advisory (HCSEC-2026-25) addressing multiple undisclosed vulnerabilities affecting Consul Community Edition and Consul Enterprise. The affected versions include Consul Community Edition prior to 2.0.3, and Consul Enterprise versions prior to 2.0.3, 1.22.11, and 1.21.17. While the advisory provides information regarding the remediation paths, it does not detail specific exploitation techniques, CVE identifiers, or observed malicious behavior. Administrators of Consul infrastructure should review the official HashiCorp Discuss security page and apply the recommended software updates to the specified versions to ensure the security and stability of their service mesh and configuration management environments.

## Impact

Failure to apply the necessary security updates leaves Consul installations exposed to potentially exploitable vulnerabilities. Organizations utilizing Consul for service discovery, configuration, and segmentation across cloud, Linux, Windows, or macOS environments are encouraged to prioritize patching to avoid potential compromise of sensitive infrastructure control planes.

## Recommendation

- Review the official HashiCorp advisory (HCSEC-2026-25) at the provided URL.
- Patch all instances of Consul Community Edition to version 2.0.3 or higher.
- Patch all instances of Consul Enterprise to versions 2.0.3, 1.22.11, or 1.21.17, depending on the current branch.
