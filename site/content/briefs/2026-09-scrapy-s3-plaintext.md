---
title: Scrapy S3DownloadHandler Vulnerable to Credential Exposure via Plaintext HTTP
slug: 2026-09-scrapy-s3-plaintext
description: The Scrapy S3DownloadHandler defaults to sending signed AWS S3 requests over plaintext HTTP, potentially exposing AWS authorization headers and security tokens to network-based attackers.
date: "2026-09-03T00:03:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:scrapy:scrapy:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud
  - web-scraping
vendors:
  - Scrapy
products:
  - Scrapy (< 2.17.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The generated request is then signed with configured AWS credentials, so AWS authorization material can be sent without TLS.
    confidence_band: high
cves:
  - id: CVE-2026-84366
    cvss: 7.4
references:
  - https://github.com/advisories/GHSA-76g3-c3x4-crvx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84366
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Scrapy to 2.17.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies 2.17.0 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Force HTTPS in Scrapy code via request.meta['is_secure'] = True.
      owner: Security Engineering
      addresses: CVE-2026-84366
      evidence: Mitigation documented in advisory.
---

The Scrapy web crawling framework contains a security vulnerability (CVE-2026-84366) in its `S3DownloadHandler` component. By default, when a user initiates a request to an `s3://` URI, the handler constructs an HTTP URL (`http://bucket.s3.amazonaws.com/key`) unless the `request.meta["is_secure"]` flag is explicitly set to `True`. Because the request is signed with the user's AWS credentials before being dispatched, the authorization headers and security tokens are transmitted over plaintext HTTP. This behavior persists in all versions of Scrapy prior to 2.17.0.

This issue is particularly critical for environments where Scrapy workers operate in untrusted network segments or where traffic is subject to interception. Attackers capable of observing or intercepting network traffic can capture valid AWS credentials or perform full Man-in-the-Middle (MITM) attacks to manipulate data being scraped, potentially leading to downstream data poisoning or influence over the crawl process.

## Impact

Successful exploitation allows a network attacker to capture sensitive AWS authorization material, including long-lived IAM keys or temporary session tokens (via `X-Amz-Security-Token`). Additionally, the ability to perform MITM attacks against the plaintext stream enables the injection of malicious content into the scraped dataset, the corruption of HTTP caches, and the redirection of crawlers to attacker-controlled targets. This vulnerability affects any organization utilizing Scrapy to interact with S3-compatible storage using IAM-based authentication.

## Recommendation

- Upgrade Scrapy to version 2.17.0 or later immediately to resolve the default insecure connection behavior.
- Audit existing Scrapy spiders for usage of `s3://` URIs and explicitly set `request.meta["is_secure"] = True` for all S3 requests if an immediate upgrade is not feasible.
- Implement network-level egress filtering and enforce TLS for all outgoing storage traffic to detect or prevent non-encrypted AWS API communications.
- Rotate any AWS IAM credentials that have been used by Scrapy instances operating in environments susceptible to network eavesdropping.
