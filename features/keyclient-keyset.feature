Feature: A verifier caches the key set of a name and keeps verifying when custody is down

  A verifier never asks custody per token. It polls the key set a name publishes,
  holds it in memory, and checks every token against that memory. Custody being
  unreachable does not empty the cache, and a key set that is malformed or
  ambiguous is refused whole, so the cache keeps what it had. A kid the cache has
  never held is refused, whether custody is up or down and whichever method asks.

  @decided 2026-10-18: verifiers hold the published key set of a name and keep
  verifying on it while custody is unreachable; a token whose key id is not in the
  set is refused, and reading the set never makes a call to custody.

  # @test:TestAPolledKeyVerifiesATokenThroughDelegation
  Scenario: A key from the polled set verifies a token through the delegation check
    Given custody publishing a key set for a name with one key
    When the verifier polls the set
    Then a token signed by that key verifies through delegation.Verify

  # @test:TestWhenCustodyIsDownTheCachedKeysStillVerify
  Scenario: Cached keys keep verifying while custody is unreachable
    Given a verifier that polled a key set and custody then stops answering
    When the verifier polls again and a token signed by a cached key is checked
    Then the poll is refused and the token verifies on the cache

  # @test:TestAnUnknownKidIsRefusedFromTheCache
  Scenario: A key id the cache never held is refused while custody is up and while it is down
    Given a verifier holding a key set that does not name a second key
    When a token signed by the second key is checked with custody up and then down
    Then the token is refused both times and the lookup of the second key is refused

  # @test:TestAMalformedSetIsRefusedWholeAndTheCacheKept
  Scenario: A malformed or ambiguous key set is refused whole and the cache is kept
    Given a verifier holding a good key set
    When custody publishes sets that are missing their keys, repeat a key id, or name a key id that is not the key's thumbprint
    Then each set is refused and the held keys still verify

  # @test:TestAnEmptySetInstallsAndVerifiesNothing
  Scenario: A set with no keys is installed, so a name that publishes nothing verifies nothing
    Given a verifier holding a key set for a name
    When custody publishes an empty set for that name
    Then the set is installed and a token signed by the old key is refused

  # @test:TestReadingTheCacheNeverReachesCustody
  Scenario: Reading the cached set makes no call to custody
    Given a verifier that polled a key set
    When the cached set is read many times
    Then custody receives no request
