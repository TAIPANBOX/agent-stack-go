Feature: An agent's own access token is verified offline, by the same rules in Go and in Rust

  vouchryx gives each agent a short-lived access token of its own (RFC 9068,
  header typ at+jwt), bound by RFC 9449 DPoP to a key the agent holds. Every
  door verifies it locally, from the key set it already holds, and learns from
  it who the agent is and which unit and org the registry put it in. tokenfuse
  verifies these tokens in Rust; this package is the Go verifier wardryx, qryx
  and costcrew will use, and the two must answer every token the same way. The
  cases they must agree on are one table, `delegation/testdata/agent-token-vectors.json`,
  which this suite runs and which a Rust suite can vendor byte for byte.

  @decided 2026-10-18: each agent is issued a five-minute, DPoP-bound access
  token by vouchryx, and every door verifies it offline with identical rules,
  the Rust and the Go verifier held together by one shared table of cases.

  # @test:TestAnAgentTokenVerifiesAndCarriesItsUnitAndOrg
  Scenario: A good agent token verifies with its holder's proof
    Given an agent token vouchryx minted for this door, bound to the agent's key
    And a proof signed by that key for this request, naming this token
    When the door verifies it
    Then it learns the agent, its unit and its org from the token
    And the proof's jti, which the door makes single-use

  # @test:TestADelegationTokenIsNeverAnAgentTokenAndTheReverse
  Scenario: An agent token and a delegation token are never read as each other
    Given a token whose header typ is JWT, and a token whose header typ is at+jwt
    When the first is checked as an agent token and the second as a delegation
    Then both are refused as malformed, because typ decides both ways

  # @test:TestAnAgentTokensAudienceIsRequiredAndExact
  Scenario: The audience is required and exact
    Given a door with no audience configured
    Then it refuses every agent token, a good one included
    And a door with an audience refuses a token for another resource, for a prefix of its own, and for no resource at all

  # @test:TestAnAgentTokenFromAnotherIssuerIsRefused
  Scenario: The issuer is exact
    Given a token whose iss differs from the configured issuer by any amount, or is not one string
    When the door verifies it
    Then it is refused for its issuer

  # @test:TestTheKeyIsTheOneItsKidNamesAndTheAlgorithmComesFromIt
  Scenario: The signing key is the one the kid names, and the algorithm comes from that key
    Given a key set holding two keys during a rotation
    Then a token signed by either verifies by its own kid
    And a token naming no kid, an unknown kid, or an algorithm its key type does not permit is refused

  # @test:TestAnAgentTokenExpiresAtItsLeewayAndNotBefore
  Scenario: A token expires thirty seconds after its exp and not a second earlier
    Given a token whose exp has passed by twenty-nine seconds
    Then it still verifies
    And at thirty seconds past exp it is refused as expired

  # @test:TestAnAgentTokenIssuedInTheFutureIsRefusedPastTheLeeway
  Scenario: A token issued too far ahead of this clock is not yet valid
    Given a token whose iat is thirty-one seconds ahead of the door's clock
    Then it is refused as not yet valid
    And one whose iat is exactly thirty seconds ahead verifies

  # @test:TestAnAgentTokenNamesOneAgentAndNobodyElse
  Scenario: An agent token names one agent acting for nobody
    Given a token whose sub is not an agent URI, or names no agent after the scheme
    Or whose client_id differs from its sub, or that carries no jti, or carries an act claim
    Then it is refused as malformed

  # @test:TestAClaimTheRustVerifierCannotReadIsRefusedHereToo
  Scenario: A claim the Rust verifier cannot read is refused here too
    Given a token whose iat or exp is not a whole number of seconds, or whose unit or org is not a string
    Then it is refused, as the Rust verifier refuses a token it cannot deserialize
    And a token that simply leaves out iat, unit or org still verifies

  # @test:TestAnAgentTokenNeedsItsHoldersProofAndABinding
  Scenario: A bound token needs its holder's proof
    Given a good token presented with no proof, with a stranger's proof, or a token with no cnf.jkt
    Then the first is refused for want of a proof, the second for the wrong key, the third as unbound

  # @test:TestAProofThatDoesNotNameThisTokenIsRefused
  Scenario: The proof must name this token
    Given a proof by the right key that carries no ath, or the ath of another token of the same holder
    Then the token is refused for the wrong key

  # @test:TestAProofWhoseJtiIsTooLongToRememberIsRefused
  Scenario: A proof identifier too long to remember is refused
    Given a proof whose jti is longer than 256 bytes
    Then the token is refused for the wrong key, before anything remembers it

  # @test:TestARevokedAgentTokenIsRefusedByItsSubjectOrItsJti
  Scenario: A revoked agent is refused by its subject or by its token's jti
    Given a revocation hook that names the agent, or names this token's jti
    Then the token is refused as revoked
    And the hook was asked with the token's jti, the agent and the token's iat

  # @test:TestRevocationIsAskedLastAndOnlyForATokenThatPassedEverythingElse
  Scenario: The revocation hook is asked last
    Given a token that fails any earlier check
    Then the revocation hook is never asked about it

  # @test:TestAProofPresentedTwiceIsRefusedTheSecondTime
  Scenario: A proof is single use
    Given a good token and its proof, verified once
    When the same proof is presented again inside its window
    Then it is refused as a replay, and a fresh proof from the same holder still verifies

  # @test:TestAVerifierWithoutAReplayCacheOrARevocationHookRefusesEverything
  Scenario: A door that forgot its replay cache or its revocation hook verifies nothing
    Given a verifier given no replay cache, or no revocation hook
    Then a good token is refused as not configured, rather than verified with that check skipped

  # @test:TestARelayedAgentTokenSkipsTheProofAndNothingElse
  Scenario: A token relayed by another door is checked on everything but the proof
    Given a good token relayed without a proof
    Then it verifies and names no proof jti
    And an unbound, expired, wrongly typed or revoked token is still refused

  # @test:TestASecondUseOfOneJtiIsRefused
  Scenario: The replay cache refuses a jti it has seen inside its window
    Given a cache that recorded one jti
    Then the same jti is refused at the same moment and ten seconds later

  # @test:TestDistinctJtisAreAllAdmitted
  Scenario: The replay cache admits every jti it has not seen
    Given ten different jti values at one moment
    Then every one is admitted

  # @test:TestAJtiSurvivesEveryMomentAProofCarryingItCouldStillBeFresh
  Scenario: A jti is remembered for as long as a proof carrying it could still be fresh
    Given a jti recorded at one moment
    Then it is still refused two windows later
    And it is admitted again long after any proof carrying it could be fresh

  # @test:TestAFullCacheRefusesRatherThanForgetting
  Scenario: A full cache refuses rather than forgetting
    Given a cache whose generation is full
    Then a new jti is refused as cache full, and a jti it remembers is still refused as seen

  # @test:TestAClockThatWalksBackwardsDoesNotEmptyTheCache
  Scenario: A clock that steps backwards does not rotate the cache
    Given a jti recorded at one moment
    When the clock steps back ten windows
    Then the jti is still refused as seen

  # @test:TestEveryAgentTokenVectorIsAnsweredAsItStates
  Scenario: Every case in the shared table is answered as the table states
    Given the shared agent-token table, with tokens and proofs minted by test-only keys
    When each case is checked by the verifier it names
    Then each is accepted or refused exactly as its expected outcome says

  # @test:TestEveryReplayVectorIsAnsweredAsItStates
  Scenario: Every replay sequence in the shared table is answered as the table states
    Given the shared table's replay sequences
    When each step is recorded in a cache of the stated cap
    Then each step is admitted, refused as seen, or refused as full exactly as stated

  # @test:TestTheVectorsFileNamesItsKeysTestOnlyAndPinsTheConstants
  Scenario: The shared table's keys are test-only by name, and its constants are this package's
    Given the shared table
    Then every private key in it is named TEST_ONLY and its key set is their public halves
    And its typ, leeway, proof window, jti bound and replay generation are this package's constants

  # @test:TestTheAccessTokenHashIsRfc9449sOwnExample
  Scenario: The token hash a proof carries is RFC 9449's own
    Given the access token of RFC 9449 section 7.1
    Then its hash is the ath that section prints

  # @test:TestTwoHundredHostileStringsNeverPanicTheAgentTokenVerifiers
  Scenario: Hostile bytes never panic the agent-token verifiers
    Given two hundred seeded strings, half random bytes and half three random base64url segments
    When each is checked as an agent token, directly and relayed
    Then nothing panics and nothing is accepted

  # @test:TestTheAgentTokenVerifierTouchesNothingOutsideTheProcess
  Scenario: The agent-token verifier holds no client and reaches nothing
    Given the options the agent-token verifier takes
    Then none of them is a client, a fetcher, an endpoint or a timeout
