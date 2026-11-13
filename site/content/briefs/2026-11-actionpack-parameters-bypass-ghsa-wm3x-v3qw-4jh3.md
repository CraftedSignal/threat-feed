---
brief_id: brief-2026-11-13-actionpack-parameters-bypass-ghsa-wm3x-v3qw-4jh3
event_id: brief-2026-11-13-actionpack-parameters-bypass-ghsa-wm3x-v3qw-4jh3
revision: 1
activity_at: "2026-11-13T04:57:41Z"
title: 'Action Pack: Parameters#each_key mass assignment bypass (CVE-2026-126081)'
slug: 2026-11-actionpack-parameters-bypass-ghsa-wm3x-v3qw-4jh3
description: The Action Pack component in Ruby on Rails incorrectly handles the return value of the each_key method, which may allow attackers to bypass Active Model mass assignment protections.
date: "2026-11-13T04:57:41Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:ruby_on_rails:action_pack:*:*:*:*:*:*:*:*
vendors:
  - Ruby on Rails
products:
  - Action Pack (< 8.1.4.1, < 8.0.5.2)
cves:
  - id: CVE-2026-126081
    cvss: 7.5
    epss: 0.00625
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-8727-m6gj-mc37
  - https://github.com/rails/rails/commit/8ba746e0a786458c281060823f2ccc5c5f6312ac
  - https://github.com/rails/rails/commit/2fc8838300133931e19eed3ea6cee76a7e83f19c
  - https://github.com/advisories/GHSA-wm3x-v3qw-4jh3
---

Ruby on Rails' Action Pack component contains a vulnerability in `ActionController::Parameters#each_key` where the method returns the internal `ActiveSupport::HashWithIndifferentAccess` hash instead of the `Parameters` instance when invoked with a block. Because this returned hash lacks the `permitted?` method, it is not rejected by Active Model mass assignment mechanisms. 

## Impact

An application that passes the return value of `each_key` to mass assignment (such as `new`, `assign_attributes`, or `update`) could allow a remote, unauthenticated attacker to set attributes that the application does not permit, such as an authorization flag.

## Recommendation

Developers should avoid using the return value of `each_key` and ensure only permitted `Parameters` instances are provided to mass assignment methods.
