Feature: A chain verifier that runs on the box and tells somebody

  Measured 2026-09-17 on the appliance proving run (agent-stack-go#64): one
  byte flipped on an already-sealed line of the shared events bus was caught by
  nothing. The planes were past that line by offset and cursor, and
  `agent-conform -chain` would have named the break, but it was source in this
  repository and nothing on the box could run it.

  `agent-conform watch-dir <dir>` is that verification made runnable by a
  CronJob or a compose loop, and made to alert: it walks one flat directory,
  verifies every stream's prev_hash chain from its first line, and appends one
  agent-event per newly found problem to its own stream, where heraldyx and the
  console already look. One run, then exit: the schedule belongs to whatever
  runs it.

  The mode is held to being safe to point at a bus. It writes only its own
  output and its own state, it reads with caps, and a bus it could not read is
  an error and never a pass.

  # @test:TestWatchDirACleanChainedFileReportsNothing
  Scenario: A clean bus raises nothing
    Given a bus whose streams were written by the library's own chained writer
    When the verifier runs
    Then it exits 0, writes no alert and creates no file
    And it says which streams it verified

  # @test:TestWatchDirOneFlippedByteInAMiddleLineIsChainBrokenAtTheRightLine
  Scenario: One flipped byte is a chain_broken naming the file and the line
    Given a chained stream in which one byte of a middle line was changed
    When the verifier runs
    Then it exits 1
    And it appends one chain_broken event of severity high to its own stream
    And the event names the file, the first line whose prev_hash no longer
      matches, and the kind of break

  # @test:TestWatchDirNamesTheFirstBreakOfSeveralAndCountsThemAll
  Scenario: A stream broken in two places is reported once, at the first
    Given a stream with two separate breaks
    When the verifier runs
    Then there is one alert for that file, naming the first break
    And the alert carries the number of breaks

  # @test:TestWatchDirTheAlertItWritesConformsAndIsItselfChained
  Scenario: The alert is a well-formed event on a chain of its own
    Given a bus with a broken stream and an unchained one
    When the verifier runs
    Then every alert conforms to the v1.0 agent-event schema
    And the verifier's own stream passes the library's chain verification

  # @test:TestWatchDirASecondRunDoesNotAlertAgainForTheSameBreak
  Scenario: The same break is not announced every minute
    Given a break the verifier has already reported
    When it runs again, and again
    Then it exits 0 and appends nothing, because nothing is new

  # @test:TestWatchDirABreakThatMovesIsANewAlert
  Scenario: A break at a different line is a different finding
    Given a break reported at one line
    When the file is replaced and now breaks at another line
    Then the verifier reports the new one

  # @test:TestWatchDirAnAlertThatFailedToWriteIsNotRecordedAsReported
  Scenario: An alert that never reached the bus is not remembered as sent
    Given two new findings and a writer that fails on the second
    When the verifier runs, and then runs again with a working writer
    Then the first run exits 2 and remembers only the alert it delivered
    And the second run delivers the one that was lost

  # @test:TestWatchDirAnUnchainedFileIsReportedOnceAtLowAndNotAsBroken
  Scenario: A stream with no chain at all is unchained, not broken
    Given a stream of several events and not one prev_hash
    When the verifier runs
    Then it appends one chain_unchained event of severity low
    And it does not call the stream broken and exits 0
    And it does not repeat the alert on the next run

  # @test:TestWatchDirAFileWithOneEventIsNotYetJudged
  Scenario: A stream with a single event has nothing to judge yet
    Given a stream holding one event, which is where every chain starts
    When the verifier runs
    Then it says nothing about it

  # @test:TestWatchDirAnEmptyOrMissingDirectoryIsAnErrorNotASilentPass
  Scenario: A bus it could not find anything on is an error
    Given a missing directory, an empty one, a file instead of a directory,
      one with no stream in it, or one holding only a symlink
    When the verifier runs
    Then it exits 2 and says why, because nothing was measured

  # @test:TestWatchDirDoesNotDescendIntoSubdirectories
  Scenario: The bus is one flat directory
    Given a broken stream one directory level down
    When the verifier runs on the bus
    Then the nested stream is not part of what it checks

  # @test:TestWatchDirDoesNotFollowASymlinkOutOfTheBus
  Scenario: A link on the bus is not followed
    Given a symlink named like a stream that points at a broken file elsewhere
    When the verifier runs
    Then it names the link as skipped and reads nothing through it

  # @test:TestWatchDirNeverModifiesAFileItReads
  Scenario: It never changes a file it reads
    Given streams that are broken, unchained, empty and garbage
    When the verifier runs twice
    Then every file that existed has the same bytes afterwards
    And the only files created are its own output and its own state

  # @test:TestWatchDirCanRunAgainstAReadOnlyBusWithItsOutputElsewhere
  Scenario: It works against a bus mounted read-only
    Given a bus directory it cannot write to
    When the verifier is told to put its output and state elsewhere
    Then the alert lands there and the bus gains and loses nothing

  # @test:TestWatchDirRefusesAnOutputThatIsAnotherWritersStream
  Scenario: It cannot be pointed at somebody else's stream
    Given an output path that names another writer's stream
    When the verifier runs
    Then it exits 2 and that stream is untouched

  # @test:TestWatchDirSurvivesHostileInput
  Scenario: Hostile files do not crash it
    Given a file that is empty, binary, invalid JSON, absurdly nested,
      one enormous line, or a line with no newline at all
    When the verifier runs
    Then it never panics and never invents a chain alert
    And a file it could not read to the end is named on stderr and exits 2

  # @test:TestWatchDirAHugeLineDoesNotHideABreakThatCameBeforeIt
  Scenario: An oversize line does not hide an earlier break
    Given a stream with a break and, after it, a line over the cap
    When the verifier runs
    Then the break is still alerted
    And the run exits 2 because the file was not read to its end

  # @test:TestWatchDirCapsTheBytesItReadsPerFile
  Scenario: A file over the byte cap is never a clean pass
    Given a stream larger than the per-file cap with its break beyond the cap
    When the verifier runs
    Then it exits 2 and names the file, rather than reporting it clean

  # @test:TestWatchDirAnOversizeClaimedPrevHashDoesNotInflateTheAlert
  Scenario: A forger does not choose how big the next bus line is
    Given a forged line whose prev_hash is hundreds of kilobytes long
    When the verifier alerts on it
    Then the alert stays small

  # @test:TestWatchDirVerifiesItsOwnOutputToo
  Scenario: Its own alerts are a stream like any other
    Given the verifier's output was edited after it was written
    When the verifier runs again
    Then it reports that file as broken

  # @test:TestWatchDirACorruptStateFileIsAnErrorNotAFreshStart
  Scenario: A state file it cannot read is an error
    Given a state file that is not valid
    When the verifier runs
    Then it exits 2, writes no alert and leaves the state file as it was

  # @test:TestWatchDirThroughTheRealBinaryExitsWithTheDocumentedCodes
  Scenario: The exit codes hold in the real binary
    Given the built agent-conform
    When it runs on a broken bus, again, on a missing directory, and with no argument
    Then it exits 1, 0, 2 and 2

  # @test:TestWatchDirEveryLoopsAndStopsCleanly
  Scenario: A compose service can repeat the pass without a shell to loop in
    Given the verifier started with an interval
    When a clean pass is followed by one that finds a new break
    Then it keeps going, alerts the break once, and prints nothing for a quiet pass
    And it exits 0 when it is told to stop

  # @test:TestWatchDirEveryExitsTwoWhenAPassCannotDoItsJob
  Scenario: A looping verifier that cannot verify does not look healthy
    Given the verifier started with an interval on a bus with nothing to verify
    When a pass cannot do its job
    Then it exits 2 at once, so a supervisor restarting it shows the failure
