Feature: A plain writer takes the file lock that a shared stream needs

  The events bus is a directory of NDJSON streams, and a stream can have more
  than one writer in more than one process. The chained writer locks the file
  for each append, and a plain writer that another process also appends to
  needs the same lock: on an NFS share two appends can otherwise overwrite one
  another. Measured on a shared volume across two nodes on 2026-10-14, the
  chained writer without the lock lost half of its events and no write
  reported it. The plain writer had the same unlocked append and was not
  measured on its own.

  @decided 2026-10-14: the plain writer takes the same exclusive lock on the
  file for the length of one append; red tests come first, mutants are named,
  and a lock that cannot be taken appends nothing.

  # @test:TestTheWriterLockIsHeldWhileTheLineIsAppended
  Scenario: Another open file cannot take the lock while a plain writer appends
    Given a plain writer on one stream
    When it appends one event
    Then a second open file of that stream cannot take the lock while the line is being written
    And the lock is free again when the append returns

  # @test:TestAWriteWaitsForAnotherWritersLock
  Scenario: A plain writer waits for a lock another writer holds
    Given another writer holds the lock on the stream
    When a plain writer is asked to append an event
    Then the append does not complete while the other writer holds the lock
    And it completes, with its line on disk, once the lock is released

  # @test:TestTheWriterLockIsReleasedWhenAnAppendPanics
  Scenario: A panic during an append still releases the lock
    Given a plain writer whose append panics after it takes the lock
    When the panic is recovered by the caller
    Then the lock was held when the panic came
    And the lock is free afterwards, so other writers of the stream are not stalled

  # @test:TestNothingIsWrittenWhenTheWriterCannotBeLocked
  Scenario: A plain writer appends nothing when it cannot take the lock
    Given a plain writer whose stream cannot be locked
    When it is asked to append an event
    Then the append returns the lock error
    And no line is added to the stream

  # @test:TestAFailureToReleaseTheWriterLockIsReported
  Scenario: A failure to release the lock is reported, although the line is on disk
    Given a plain writer whose lock cannot be released
    When it appends an event
    Then the append returns the unlock error
    And the line is on the stream
