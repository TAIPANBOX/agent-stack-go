Feature: A DPoP proof means exactly what it claims, and a key's curve matches its algorithm's name

  Measured 2026-09-17 with this package's own tests below, red at `da26c65`
  and green at `222702f`: the 2026-09-17 delegation review's probe suite
  (TestCodexReplayWindowRemembersFutureDatedProofUntilItExpires,
  TestCodexDPoPBindingPreservesCaseSensitivePathAndMethod,
  TestCodexInvariant1ES256MustNotAcceptP384Key,
  TestCodexInvariant19MalformedSnapshotCannotEraseKnownRevocation) first
  showed four findings (F3, F4, F6, F7; F3 and F4 rated MEDIUM, F6 and F7
  rated LOW by that review) against the unchanged code, closed by the
  scenarios below.

  Four checks in this package each resolved an ambiguous boundary toward the
  friendlier of two readings instead of the strict one their own doc comments
  already promised.

  F3: the replay window forgot a future-dated proof before the proof itself
  went stale, so a captured proof with iat up to 60 seconds ahead could be
  replayed once its entry aged out, for as long as its own freshness had left.

  F6: htm and htu folded case over the whole method and the whole URL, so a
  proof bound to POST /v1/token also verified post and /v1/TOKEN, and nothing
  tested the host or the scheme on their own either. RFC 9110 methods are
  case sensitive, and RFC 9449 section 4.3 asks for the scheme and host rule
  of RFC 3986 section 6.2.2.1, which also folds the case of percent-encoding
  hex digits; comparing the path without that fold is a stricter choice
  section 4.3 permits, since it states its own normalisations as a SHOULD.

  F7: ES256 and ES384 named an algorithm without checking the curve behind it,
  so a P-384 key with its own 96-byte signature verified under the name
  ES256, SignES256 signed with whatever curve it was handed, and curveName
  labelled every curve that is not P-384 as P-256, publishing a P-521 key as
  though it were one.

  F4: ParseSnapshot read a missing revocations member, a null one, or one
  holding a null entry as zero valid revocations rather than a refusal, so
  Install replaced a complete held list with an empty-looking one and a known
  revocation stopped being held.

  @decided 2026-09-17: the four findings F3, F4, F6 and F7 of that review
  (two MEDIUM, two LOW) are closed as measured.

  # @test:TestAFutureDatedProofIsRememberedUntilItsOwnFreshnessEnds
  Scenario: A future-dated proof is remembered for exactly as long as it could still be fresh
    Given a proof whose iat is between 1 and 60 seconds ahead of now
    When it is presented once, then presented again 61 seconds later
    Then the second presentation is refused as a replay, not accepted, all the
      way to the last instant the proof could still be fresh, and refused as
      stale one second past that

  # @test:TestABackwardDatedProofIsForgottenNoLaterThanItsOwnFreshnessEnds
  Scenario: A backward-dated proof is forgotten no later than its own freshness ends
    Given a proof whose iat is 30 seconds behind now, presented once
    When 31 seconds pass and another proof is checked, which is what actually
      sweeps the seen-set
    Then the backward-dated proof's own entry is gone from the seen-set and
      presenting it again is refused as stale

  # @test:TestTheMethodBindingIsCaseSensitive
  Scenario: The method binding is case sensitive
    Given a proof bound to POST
    When it is presented for post, Post and POst
    Then every one is refused as a binding mismatch

  # @test:TestThePathBindingIsCaseSensitive
  Scenario: The path binding is case sensitive
    Given a proof bound to /v1/token
    When it is checked against /v1/TOKEN and against the relative /V1/token
    Then both are refused as a binding mismatch

  # @test:TestTheSchemeAndHostStillFoldCase
  Scenario: The scheme and the host still fold case
    Given a proof bound to https://vouchryx.internal/v1/token
    When it is checked against HTTPS://VOUCHRYX.INTERNAL/v1/token
    Then it verifies, because only the scheme and the host are allowed to fold

  # @test:TestAProofForAnotherHostOrSchemeIsRefused
  Scenario: A proof for another host or another scheme is refused
    Given a proof bound to https://vouchryx.internal/v1/token
    When it is checked against https://evil.internal/v1/token and against http://vouchryx.internal/v1/token
    Then both are refused as a binding mismatch

  # @test:TestARelativeOrUnparseableHtuIsRefused
  Scenario: A relative or unparseable htu binds to nothing
    Given a proof whose htu claim is a relative path or a string net/url cannot parse
    When it is checked against the correct absolute URL
    Then it is refused as a binding mismatch rather than compared as an empty string

  # @test:TestES256RefusesAP384KeyAndItsNinetySixByteSignature
  Scenario: ES256 refuses a P-384 key and its own 96-byte signature
    Given a token signed by a P-384 key, with its header naming alg ES256
    When it is verified against a set holding that P-384 key
    Then it is refused as an algorithm this key type is not permitted, never
      as a bad signature

  # @test:TestES384RefusesAP256Key
  Scenario: ES384 refuses a P-256 key, the same rule in the other direction
    Given a token signed by a P-256 key, with its header naming alg ES384
    When it is verified against a set holding that P-256 key
    Then it is refused as an algorithm this key type is not permitted

  # @test:TestFromPublicRefusesAP521Key
  Scenario: FromPublic refuses a curve it cannot name rather than mislabel it
    Given a P-521 public key
    When it is rendered as a JWK
    Then the result is the zero JWK, the same refusal an unencodable key
      already gets

  # @test:TestFromPublicNamesTheAlgorithmFromTheCurve
  Scenario: FromPublic names the algorithm the curve actually signs
    Given a P-384 public key
    When it is rendered as a JWK
    Then it carries crv P-384 and alg ES384, not the constant ES256

  # @test:TestSignES256RefusesEveryCurveButP256
  Scenario: SignES256 signs its one curve and refuses every other
    Given a P-384 key and a P-521 key
    When each is handed to SignES256
    Then both are refused, and a P-256 key goes on signing and verifying as before

  # @test:TestADPoPProofCarryingAP384KeyIsRefusedUnderTheNameES256
  Scenario: The DPoP door refuses the same P-384-as-ES256 proof the token verifier does
    Given a DPoP proof whose embedded jwk is a P-384 key and whose header names alg ES256
    When the verifier checks it
    Then it is refused

  # @test:TestAMalformedRevocationsMemberCannotEraseAKnownRevocation
  Scenario: A malformed revocations member never reaches Install, so a known revocation survives it
    Given a cache already holding a revocation for a known token
    And a snapshot body missing its revocations member, holding a null one, or holding a null entry
    When that body is parsed and, only if parsing somehow succeeded, installed
    Then parsing is refused every time and the cache still answers that the known token is revoked
