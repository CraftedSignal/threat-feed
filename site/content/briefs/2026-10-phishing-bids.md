---
brief_id: brief-2026-10-27-phishing-bids
event_id: brief-2026-10-27-phishing-bids
revision: 1
activity_at: "2026-10-27T17:53:26Z"
title: Credential Phishing via Fake Project Bid Invitations
slug: 2026-10-phishing-bids
description: A credential phishing campaign uses fake project bid invitations and password-protected PDFs to direct recipients to fraudulent document-sharing platforms and fake Microsoft login pages.
date: "2026-10-27T17:53:26Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://cofense.com/blog/locked-and-loaded-phishing-through-fake-bids-and-protected-documents
  observed_at: "2026-10-27T17:53:26Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
references:
  - https://cofense.com/blog/locked-and-loaded-phishing-through-fake-bids-and-protected-documents
iocs:
  - type: hash_sha256
    value: 9ca705d6466d4d71c3fb0cae5097933afe1de1bc139d53bb63565a52dc9ebccb
  - type: url
    value: https://slotpastimaxwin50jt.online/autoproject@autoproject.com/index.php
  - type: url
    value: https://mm-lasertechnik.lastingonlineexperiences.de/1Dmw9/?key=NKsIDYXvtY
  - type: url
    value: https://nbpn.lastingonlineexperiences.de/nasa.php
  - type: ip
    value: 67.205.150.245
  - type: ip
    value: 104.21.82.118
  - type: ip
    value: 172.67.157.109
ioc_counts:
  hash_sha256: 1
  ip: 3
  url: 3
---

Cofense Phishing Defence Centre identified a phishing campaign utilizing fraudulent project bid invitations. The emails contain password-protected PDF attachments, a tactic used to evade email security scanners that cannot inspect encrypted content. Upon opening the PDF, victims are prompted to interact with a link that mimics a OneDrive document preview. This leads to a fake document-sharing portal and subsequently a spoofed Microsoft login page designed to harvest user credentials.
