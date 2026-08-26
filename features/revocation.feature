Feature: A revocation list something actually consults

  vouchryx has served `GET /v1/revocations` since the day it was written, with
  an `as_of` cursor so a poller can tell an empty list from a failed fetch.
  Measured 2026-08-26: nothing polls it. No consumer of this module sets
  `Options.Revoked`, and tokenfuse's two doors pass a closure that answers
  false. Zero consumers, in either language.

  Four documents said the opposite in the present tense, this module's README
  among them. They are corrected in the same wave, because the estate's rule is
  to change the text rather than to narrate the change.

  The decision those sentences hide is what an enforcement point should do when
  the list it holds has gone old. The estate has answered "a dependency is
  unreachable" twice, both times defaulting to open, and this one defaults to
  closed instead. The difference is what the unreachable thing was going to
  say: a PDP you cannot reach says nothing at all, while a revocation list you
  cannot reach says something narrow and specific, which is that this authority
  can no longer be confirmed to exist. Open there would also make "revoking
  ends the right to act" conditional on one service being reachable, and would
  do it silently.

  A list from four minutes ago still holds every revocation older than four
  minutes, so the age governs a miss and never a hit.

  # @test:TestARevokedDelegationIsRefusedByVerifyAfterAPollPicksItUp
  Scenario: A revoked delegation stops working, end to end
    Given a delegation token whose signature, binding and expiry are perfect
    And an enforcement point polling a revocation service over HTTP
    When the token works, an operator revokes it, and the next poll lands
    Then Verify refuses it, which is the sentence four documents made and
      nothing performed

  # @test:TestARevokedTokenIsRefusedBySomethingThatActuallyReadTheList
  Scenario: A revoked token is refused
    Given a held list that names the token
    When an enforcement point checks it
    Then it is refused, and the answer says it came from the list

  # @test:TestATokenTheListDoesNotNameIsNotRefused
  Scenario: A token nobody revoked keeps working
    Given a held list that does not name the token
    When an enforcement point checks it
    Then it is allowed, which is what stops the refusal above from being a
      cache that refuses everything

  # @test:TestASubjectRevocationCoversWhatWasIssuedAtOrBeforeItsMoment
  Scenario: An agent is revoked without being banned
    Given the operator revoked every token issued for that agent up to a moment
    When tokens issued before, during and after that second are checked
    Then the first two are refused and the third is not, so an operator who
      revokes in order to re-issue does not wait out a lifetime

  # @test:TestAStaleListStillRefusesWhatItNames
  Scenario: A list four minutes old still holds what it already knew
    Given the poller has not succeeded for four minutes
    And the held list names the token
    When an enforcement point checks it
    Then it is still refused, because nothing un-revokes a token and calling a
      token we know is dead a live one is worse than the outage

  # @test:TestAMissOnAStaleListFallsBackToTheFailMode
  Scenario: A list too old to be complete stops answering for absence
    Given the poller has not succeeded for longer than the maximum age
    And the held list does not name the token
    When an enforcement point checks it
    Then the operator's fail mode answers instead of the list, because a miss
      is an inference from the list being complete and completeness is the
      property that expired

  # @test:TestAListExactlyAtTheMaximumAgeIsStillTrustedForAMiss
  Scenario: The boundary is the boundary
    Given a held list exactly at the maximum age
    When a token it does not name is checked
    Then it is allowed from the list rather than by the fail mode

  # @test:TestAListNobodyEverFetchedSaysSoRatherThanReadingAsEmpty
  Scenario: A poller nobody wired is not an empty list
    Given no list has ever been fetched
    When any token is checked
    Then the fail mode answers and says nothing was ever fetched, because a
      poller that has never once succeeded will not fix itself

  # @test:TestAnAnswerFromTheListIsNeverReportedAsAFallback
  Scenario: An operator can tell a real answer from a fallback
    Given a list young enough to answer
    When tokens both in it and absent from it are checked
    Then neither answer is reported as a fallback, so a count of fallbacks
      measures outages rather than traffic

  # @test:TestACursorThatMovedBackwardsIsRefusedAndDoesNotResetTheAge
  Scenario: An answer describing an earlier moment never replaces a later one
    Given a held list with a cursor
    When a fetch returns a list whose cursor is earlier
    Then it is refused and counted, the newer list is kept, and the age is not
      reset, because installing it would make a view that had stopped moving
      start reading as fresh

  # @test:TestACursorThatDidNotMoveIsAcceptedBecauseASecondIsACoarseClock
  Scenario: Two fetches in one second are not a fault
    Given the cursor is a Unix second
    When two fetches return the same cursor
    Then the second applies, because refusing it would break any poller faster
      than once a second

  # @test:TestASnapshotWithNoCursorIsRefusedRatherThanAgedFromNothing
  Scenario: A list with no cursor cannot be aged, so it is not installed
    Given a fetch returns a list carrying no `as_of`
    When it is offered to the cache
    Then it is refused and the enforcement point still reports never having
      fetched anything

  # @test:TestAnEntryNamingNeitherATokenNorASubjectMatchesNothing
  Scenario: A malformed entry revokes nothing rather than everything
    Given an entry naming neither a token id nor a subject
    When any token is checked against it
    Then it matches nothing, because comparing two empty ids would revoke
      every token that carries none

  # @test:TestAnEntryPastItsOwnExpiryStopsMatching
  Scenario: An entry stops mattering once the last token it could match has expired
    Given an entry carrying its own expiry
    When a token is checked before and after that moment
    Then it matches only before, so the list does not grow for ever

  # @test:TestAnEntryWithNoStatedExpiryIsKeptRatherThanDropped
  Scenario: An entry with no stated expiry is kept rather than dropped
    Given a producer that stated no expiry
    When a token it names is checked long afterwards
    Then it still matches, because dropping early makes a revoked token work
      and keeping late only outlives a token that has expired

  # @test:TestTheHookIsTheShapeOptionsRevokedTakesAndShowsTheCallerTheBasis
  Scenario: Wiring it in shows the caller what each answer rested on
    Given an enforcement point filling `Options.Revoked` from this cache
    When it checks a revoked token and a live one
    Then it gets the plain answer Verify needs, and separately sees the basis,
      so a fallback cannot pass unnoticed

  # @test:TestTheRequestPathCannotBecomeANetworkCall
  Scenario: The check cannot quietly become a round trip
    Given the request path and the poller are different methods
    When their shapes are read
    Then nothing on the request path takes a context or returns an error, and
      the one method that reaches the network does take one

  # @test:TestAFetchThatFailsLeavesTheHeldListAgeing
  Scenario: A failed poll is not an empty list
    Given a revocation service that is answering errors
    When a poll fails
    Then the held list is untouched and goes on ageing, which is what
      eventually hands the question to the fail mode

  # @test:TestANonTwoHundredAnswerIsNeverReadAsAnEmptyList
  Scenario: Something in front of the service answering an error with a body
    Given a gateway answering 503 with a perfectly well-formed revocations body
    When a poll reads it
    Then it is refused on the status alone, because installing it would put an
      empty list over a good one

  # @test:TestAnOverlongRevocationListIsRefusedRatherThanTruncated
  Scenario: A list too large to read is refused rather than shortened
    Given a body over the cap
    When a poll reads it
    Then it is refused, because a truncated revocation list is a SHORTER one
      and that is the direction that lets a revoked token work

  # @test:TestTheBodyVouchryxServesParsesIntoThis
  Scenario: The body vouchryx actually serves is the body this reads
    Given a response copied from a live `GET /v1/revocations`
    When it is parsed
    Then both entry shapes come through with their cursor

  # @test:TestABodyThatIsNotAListAtAllIsAnErrorRatherThanAnEmptyList
  Scenario: Something else answering on that port is not an empty list
    Given a body that is not a revocations object
    When it is parsed
    Then it is an error rather than an empty list, including the JSON array a
      derived decoder would otherwise read into an empty snapshot

  # @test:TestAnEmptyListIsAListAndNotAFailure
  Scenario: An empty list is knowledge
    Given a fetch that succeeded and returned no revocations
    When a token is checked
    Then it is answered from that list rather than by the fail mode

  # @test:TestAPollerAndARequestPathDoNotRace
  Scenario: A poller writes while request paths read
    Given many goroutines installing and checking at once
    When the suite runs under the race detector
    Then nothing races, which is the shape this type exists in

  # @test:TestTheDefaultFailModeRefuses
  Scenario: An operator who never chose a fail mode gets the safe one
    Given a deployment that wired a poller and named no fail mode
    And no list has ever been fetched
    When any token is checked
    Then it is refused, because the default an operator falls into is the one
      that breaks loudly rather than the one that breaks silently
