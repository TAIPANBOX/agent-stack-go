Feature: The Go binding at 1.0 accepts both Passport versions and holds its own surface

  @decided 2026-09-12: the shared contract is frozen at 1.0 (agent-passport
  SPEC 10). This module is its Go form, so two things follow. A consumer that
  imports it MUST accept Passport v0.1 and v1.0 and event v0.1, v0.2 and v1.0
  (SPEC 6.4.1, 7); and a change to what this module exports is a version
  decision, which until now was a sentence in CLAUDE.md and nothing else.

  Scenario: a v1.0 Passport parses
    Given a Passport document stamped taipanbox.dev/agent-passport/v1.0
    When it is parsed
    Then it is accepted and its schema string is kept
  # @test:TestParseAcceptsAV10Passport

  Scenario: a v0.1 Passport keeps parsing after 1.0
    Given a Passport document stamped taipanbox.dev/agent-passport/v0.1
    When it is parsed
    Then it is accepted exactly as before
  # @test:TestParseStillAcceptsAV01Passport

  Scenario: a v1.0 Passport carrying a key the schema never named is refused
    Given a v1.0 Passport document with agent_id written beside id
    When it is parsed
    Then it is refused with a sentinel error that names the key
  # @test:TestParseRefusesAV10PassportWithAKeyTheSchemaNeverNamed

  Scenario: the same key on a v0.1 Passport is tolerated, by decision
    Given a v0.1 Passport document with the same extra key
    When it is parsed
    Then it is accepted, because v0.1 keeps its hole
  # @test:TestParseToleratesTheSameKeyUnderV01

  Scenario: a version this module does not carry is refused
    Given a Passport document stamped a version that is neither v0.1 nor v1.0
    When it is parsed
    Then it is refused as an unsupported schema, never mapped onto a known one
  # @test:TestParseRefusesAnyOtherSchemaString

  Scenario: the golden Passport conforms to the closed v1.0 schema
    Given the golden Passport this package's own tests use
    When it is stamped v1.0 and validated against the vendored v1.0 schema
    Then it conforms, which proves the struct emits no key the schema never named
  # @test:TestGoldenPassportConformsToV10

  Scenario: an event with a claimed subject conforms under v1.0
    Given an Event stamped taipanbox.dev/agent-event/v1.0 whose subject is claimed
    When it is validated against the vendored v1.0 schema
    Then it conforms, because v1.0 is v0.3's shape
  # @test:TestEventWithAClaimedSubjectConformsToV10

  Scenario: agent-conform validates a v1.0 Passport against the v1.0 schema and not another
    Given a v1.0 Passport document with a key the schema never named
    When agent-conform checks it
    Then it fails under the v1.0 schema, and the same document stamped v0.1 passes
  # @test:TestCheckFileV10PassportRefusesAKeyTheSchemaNeverNamed

  Scenario: agent-conform validates a v1.0 event stream
    Given an NDJSON line stamped taipanbox.dev/agent-event/v1.0
    When agent-conform checks it
    Then it conforms, and a claimed subject conforms under it as well
  # @test:TestCheckFileValidEventStreamV10

  Scenario: a Passport stamped a version agent-conform does not carry fails outright
    Given a Passport document stamped taipanbox.dev/agent-passport/v2.0
    When agent-conform checks it
    Then it fails rather than falling back to a version it knows
  # @test:TestCheckFileUnrecognizedPassportSchemaFails

  Scenario: the exported surface is a file, and removing an export fails the gate
    Given api/surface.txt, the surface promised at 1.0
    When an exported declaration is removed or its signature changes
    Then scripts/api-surface.sh fails and names the line, unless a new major is being cut
  # @test:TestTheSurfaceFileIsWhatTheSourceExports
