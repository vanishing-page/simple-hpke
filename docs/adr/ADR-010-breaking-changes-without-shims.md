# ADR-010: Breaking API changes ship without compatibility shims

**Date:** 2026-08-21

## Context

The package is pre-1.0 and its main consumer is a chat app maintained
alongside it. Deprecated aliases (for example keeping `enc` next to
`wrapped`, or keeping usage-widening for supplied keys) would double the
API surface and the test matrix, and would keep misleading names alive.

## Decision

Breaking API changes ship as a minor-version bump (0.x semver) with no
deprecated aliases or compatibility shims. The consuming app updates in
lockstep.

- Each breaking change gets a commit whose message contains
  `BREAKING CHANGE:`. The CHANGELOG is regenerated from git history by
  `auto-changelog` on `npm version`, so the note must live in the commit,
  not in a hand edit.
- The wire formats are held to a stricter standard and do not change in
  these releases (see
  [ADR-004](ADR-004-minimal-unversioned-wire-formats.md)). API breaks are
  acceptable; envelopes produced by an older version must still open.

## Consequences

- The API stays small and names stay accurate.
- Third-party consumers get no deprecation window; an upgrade across a
  minor version may require code changes.
- This policy should be revisited at 1.0, when outside consumers matter
  more than lockstep updates.
