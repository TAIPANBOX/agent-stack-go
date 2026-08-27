Feature: The delegation cap counts the same thing at both ends

  agent-passport SPEC 5.1 says "Maximum chain depth is 32 entries", and section
  5 calls the members of `on_behalf_of` entries: the root, usually a human, is
  the first of them. So the bound is on the assembled chain.

  Package delegation builds that chain out of an RFC 8693 token, where the
  subject is deliberately NOT an actor, so the chain is `[sub] + reverse(act)`.
  Measured 2026-08-27: it bounded the ACTOR list at 32 and then prepended the
  subject. A token carrying 32 actors verified at the door and produced a
  33-entry chain, which package chain, the vendored v0.2 and v0.3 envelope
  schemas and agent-conform all refuse:

      maxItems: got 33, want 32
      chain: exceeds max depth: 33 entries, max 32

  Every one of those doors was right and the producer was wrong. Nothing was
  broken inside either package, which is why neither suite could see it: the
  bound and the assembly were one rule split across two packages, and the only
  test that can catch that is one that holds them against each other.

  THIS CHANGES WHAT Verify ACCEPTS. A delegation token that names a subject and
  32 actors verified before this change and is refused as malformed after it.
  The tokens it refuses are exactly the tokens whose records were being
  quarantined, so nothing that worked end to end stops working, but a door's
  answer has changed and that is an enforcement change rather than a tidy-up.

  # @test:TestEveryChainThisPackageHandsOutIsOneTheRecordWillHold
  Scenario: Nothing is built that the record cannot hold
    Given every actor count from none up to four past the cap
    And a token with a subject and a token without one
    When a chain is assembled from each
    Then either it is refused, or package chain accepts it, and never a chain
      handed out for a record to quarantine

  # @test:TestTheSubjectCountsTowardsTheCapBecauseTheSpecCountsEntries
  Scenario: The subject is an entry, so it counts
    Given a token naming a subject
    When it carries 31 actors and then 32
    Then the first assembles into exactly 32 entries and the second is refused
      as too deep

  # @test:TestAChainWithNoSubjectStillGetsTheWholeCap
  Scenario: A machine-to-machine chain keeps the whole budget
    Given a token with no subject, because no human is at the root
    When it carries 32 actors
    Then the chain is those 32 actors and it is accepted, because capping the
      actors at 31 unconditionally would refuse a chain the SPEC allows
