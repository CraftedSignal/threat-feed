---
title: "Subscribe"
description: "Get filtered alerts when matching briefs land — by email, Slack, or Microsoft Teams."
layout: subscribe
---

Pick a delivery channel and the filters you care about. We'll send a notification when a brief matches every filter you've selected.

The simplest case — get every critical threat — is two clicks. Beyond that, every filter narrows the feed (filters AND across categories, OR within each).

## Pre-baked feeds (no signup)

If you don't need compound filters, every taxonomy term has its own RSS feed:

- **All briefs** — `/feed.xml`
- **By severity** — `/severities/critical/feed.xml`, `/severities/high/feed.xml`, …
- **By type** — `/types/threat/feed.xml`, `/types/coverage/feed.xml`, …
- **By product** — `/products/<slug>/feed.xml`
- **By actor** — `/actors/<slug>/feed.xml`
- **By tag** — `/tags/<slug>/feed.xml`

Slack supports RSS natively (`/feed subscribe <url>`). Teams has an "RSS" connector. For email, paste an RSS URL into Buttondown, Feedrabbit, or Follow.it.
