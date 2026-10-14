Feature: Writers that share one stream produce one chain

  The events bus is a directory of NDJSON streams, and a stream does not always
  have one writer. A pod being replaced keeps appending through its termination
  grace period while its successor has already resumed the chain, and a service
  and its CronJob append to one file by design. Until this change a
  ChainedWriter stamped prev_hash from the hash of its OWN previous write, held
  in memory, so every such interleaving was reported as a broken chain on an
  honest stream: measured on a three-node cluster on 2026-10-14, where the
  watch-dir verifier reported chain_broken on the policy service's stream at
  line 160 after its pod was deleted.

  @decided 2026-10-14: the writer locks the file, reads the last line on disk
  under the lock, stamps prev_hash from that line, appends, and only then
  unlocks; red first, mutants named, and measured live on a shared volume
  across two nodes before anything depends on it.

  # @test:TestAWriteChainsFromTheLineAnotherWriterAppended
  Scenario: A writer chains from the line another writer appended, not from its own last line
    Given two writers on one stream
    When the first appends, then the second, then the first again
    Then the first writer's second event carries the hash of the second writer's line
    And the stream verifies as one chain with no break

  # @test:TestConcurrentWritersOnOneFileKeepOneChain
  Scenario: Many writers appending at once in one process keep one chain
    Given between two and eight writers on one stream, two of them sharing one writer object
    And a tenth of the lines longer than the first read from the end of the file
    When they all append at once, swept over twelve seeds
    Then the stream verifies as one unbroken chain
    And every writer's events are present once each, in the order it wrote them

  # @test:TestConcurrentProcessesOnOneFileKeepOneChain
  Scenario: Many processes appending at once keep one chain
    Given four processes, each with its own writer on one stream
    When they are released at once and each appends two hundred events
    Then the stream verifies as one unbroken chain of eight hundred events

  # @test:TestAWriteWaitsForTheFileLockAndReadsTheTailAfterIt
  Scenario: A write waits for the lock and reads the end of the file only once it holds it
    Given another open file holds the lock on the stream
    When a writer is asked to append
    Then it does not append while the lock is held
    And once the holder has appended a line and released the lock, the writer chains from that line

  # @test:TestTheFileLockIsHeldWhileTheLineIsAppended
  Scenario: The lock is still held while the line is appended and released afterwards
    Given a writer appending to a stream
    When another open file tries to take the lock at the moment the line is appended
    Then it is refused
    And it is granted once the write has returned

  # @test:TestAWriteAfterATornTailStartsALineOfItsOwn
  Scenario: An event after a writer died mid-line is not glued onto the fragment
    Given a stream that ends in half a line with no newline
    When a writer appends an event
    Then the fragment stays one malformed line and the event is a line of its own
    And the event starts a fresh chain, which is a restart and not a break

  # @test:TestALastLineLongerThanOneReadStillChains
  Scenario: A long last line is found by reading further back
    Given a stream whose last line is longer than the first read from its end
    When a writer appends an event
    Then the event chains from that long line

  # @test:TestALastLineLongerThanTheWindowStartsAFreshChain
  Scenario: A last line longer than the verifier reads starts a fresh chain
    Given a stream whose last line is longer than the verifier's line cap
    When a writer appends an event
    Then the event starts a fresh chain rather than the writer reading without bound

  # @test:TestBlankLinesAtTheEndAreSkippedAndABlankFileIsAHead
  Scenario: Blank lines at the end of a stream are not lines
    Given a stream that ends in blank lines after an event
    When a writer appends an event
    Then the event chains from the event before the blank lines

  # @test:TestNothingIsWrittenWhenTheFileCannotBeLocked
  Scenario: Nothing is appended without the lock
    Given a stream that cannot be locked
    When a writer is asked to append, or a writer is opened on it
    Then the append is refused with the lock's error and the stream is unchanged
    And opening the writer fails rather than its first event

  # @test:TestAFailureToReleaseTheLockIsReported
  Scenario: A lock that could not be released is reported
    Given a stream whose lock cannot be released
    When a writer appends an event
    Then the event is on disk and the write still reports the failed release

  # @test:TestNothingIsWrittenWhenTheTailCannotBeRead
  Scenario: Nothing is appended when the end of the stream cannot be read
    Given a stream whose end cannot be read
    When a writer is asked to append
    Then the append is refused rather than guessed to be a head

  # @test:TestAPanicWhileAppendingStillReleasesTheLock
  Scenario: A panic while appending does not leave the stream locked
    Given a caller that recovers from a panic, as an HTTP server does per request
    When an event that panics while it is encoded is written
    Then the lock is released and the same writer appends the next event
