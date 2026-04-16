-- Entries written before the ML-DSA-65 switch (v0.1.2 and earlier) were
-- signed with Ed25519. Their 64-byte signatures will not verify under the
-- new scheme, and keeping them around would confuse both route
-- materialization and the operator. The project is pre-release, no real
-- state is lost.
--
-- See `docs/superpowers/specs/2026-04-15-pq-sigs-design.md` §5.2.
DELETE FROM entries;
