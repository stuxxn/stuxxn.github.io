---
layout: post_collection
date:   2026-03-02
categories: [advisory]
advisory_tag: drivelock_multi_2026_patch_analysis

title:  "[PatchAnalysis - DriveLock] DriveLock Enterprise Service 25.2.4 hidden vulnerabilites "
advisory:
  product: DriveLock
  homepage: https://www.drivelock.com/
  vulnerable_version: "< 25.2.4, < 25.1.7, < 24.2.9"
  fixed_version: "25.2.4, 25.1.7, 24.2.9"
  found: 2026-02-27
---

As the `DriveLock Enterprise Service` version `25.2.4.62569` released on `2026-02-20` includes patches for other vulnerabilites I submitted to the vendor - `ZDI-CAN-28726`, `ZDI-CAN-28713 / ZDI-CAN-28722 / ZDI-CAN-28746`, `ZDI-CAN-28719` - I did a patch analysis if the applied mitigations can be bypassed somehow.

At a first glance it seems that the patches can not be bypassed.

But having a closer look at the patch-diff reveleaed that the patch also closes security vulnerabilites not mentioned on the [patch notes](https://www.drivelock.help/versions/2025_2/web/en/releasenotes/Content/ReleaseNotes_DriveLock/BugFixes/NeueBugFixes2025-2PA2.htm).

This post gives you an overview about these silently patched vulnerabilites and a working `Proof of Concept`.


# Timeline

* 2026-02-20: DriveLock Enterprise Service, Version 25.2.4 release
