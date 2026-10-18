Feature: A consumer holds the keys custody certifies for it, and renews them before they expire

  A consumer that signs at a high rate keeps its own key in memory and has custody
  certify it. Custody never sees the private key: the consumer proves it holds the
  key by signing a challenge, and gets back a statement custody signed. The consumer
  signs locally only while that statement is valid, asks for the next one at half
  its life, and never signs with a key whose statement has run out. A held key is
  the other kind: custody signs it on request, and the consumer carries only the
  credential that says who it is. The credential is a unix socket, a key file, or a
  Kubernetes projected token, one of the three and never a guess between them.

  @decided 2026-10-18: a consumer's own signing keys are certified by custody and
  renewed by the consumer before they expire, and a key whose statement has run out
  is never used to sign. The credential is one of the three forms the launcher gives
  and a request with any other is refused before it is sent.

  # @test:TestDelegationCertifiesAKeyTheConsumerHolds
  Scenario: A delegated key is certified for the consumer that holds it
    Given custody and a consumer that asks for a delegated key
    When the consumer asks for the key
    Then custody certifies the thumbprint of the consumer's own public key
    And the consumer signs locally with a key custody has certified

  # @test:TestRenewalIsAskedForAtHalfLife
  Scenario: The consumer asks for the next statement at half the life of the current one
    Given a delegated key with a life of one hour
    When the consumer is asked to renew before half of that hour has passed
    Then no request reaches custody
    And at half of that hour a new statement is requested

  # @test:TestAPublishAheadKeyIsNotUsedBeforeItsNotBefore
  Scenario: A renewed key is not used to sign before custody says it is valid
    Given a renewal that custody answers with a not_before ten minutes ahead
    When the consumer signs before that time
    Then the signature is made with the key that is still valid
    And after that time the signature is made with the renewed key

  # @test:TestAnExpiredStatementIsNeverUsedToSign
  Scenario: No key is used to sign once its statement has run out
    Given a delegated key whose renewal custody refuses
    When the consumer signs after the statement has run out
    Then no signature is made
    And the consumer reports that no key is valid

  # @test:TestAFailedRenewalIsRetriedAfterAWaitNotAtOnce
  Scenario: A failed renewal is retried after a wait and is not hammered
    Given a delegated key at half its life and custody refusing the renewal
    When the consumer renews twice in quick succession
    Then the second attempt does not reach custody
    And after the wait a further attempt reaches custody

  # @test:TestAStatementForAnotherKeyIsRefused
  Scenario: A statement that certifies another key is refused and not kept
    Given custody that answers a renewal with a statement for a different key
    When the consumer renews
    Then the renewal is refused
    And the consumer holds no key

  # @test:TestAStatementForAnotherConsumerIsRefused
  Scenario: A statement that names another consumer is refused and not kept
    Given custody that answers a renewal with a statement owned by another consumer
    When the consumer renews
    Then the renewal is refused
    And the consumer holds no key

  # @test:TestAStatementOfAnotherLifetimeIsRefused
  Scenario: A statement whose life is not the one asked for is refused
    Given custody that answers a renewal with a statement of a different life
    When the consumer renews
    Then the renewal is refused

  # @test:TestALifetimeBelowTheMinimumIsRefusedBeforeAnyRequest
  Scenario: A life below the minimum custody accepts is refused before a request is made
    Given a consumer configured with a life of five minutes
    When the consumer is set up for a delegated key
    Then the set up is refused and custody receives no request

  # @test:TestAHeldKeyIsSignedByCustody
  Scenario: A held key is signed by custody with the consumer's credential
    Given custody holding a key the consumer may sign with
    When the consumer asks custody to sign a message for a purpose
    Then custody receives the message and the purpose
    And the signature answered names the key that custody used

  # @test:TestEveryRequestCarriesTheCredentialFileAsItIsNow
  Scenario: A rotated credential file is used on the next request
    Given a consumer whose credential is a file
    When the file is replaced with a new token between two requests
    Then the second request carries the new token

  # @test:TestTheSocketCredentialSendsNoBearer
  Scenario: A consumer on its own socket sends no bearer credential
    Given custody listening on the consumer's own unix socket
    When the consumer signs a message
    Then custody receives the request with no authorization header

  # @test:TestACredentialNamingTwoWaysOrNoneIsRefused
  Scenario: A configuration naming two credentials, or none, is refused
    Given a configuration with a socket and a key file, and one with neither
    When each is set up
    Then both are refused

  # @test:TestAnErrorNeverCarriesTheCredential
  Scenario: A refusal from custody does not put the credential into the error
    Given a consumer whose credential custody refuses
    When the consumer signs a message
    Then the error names the refusal and not the credential

  # @test:TestARedirectIsNotFollowedWithTheCredential
  Scenario: A redirect from custody is not followed, so the credential never goes elsewhere
    Given custody that redirects its requests to another host
    When the consumer signs a message
    Then the other host receives no request
    And the consumer reports the refusal
