Feature: A signed checkpoint says what a stream held, and a writer creates files safely

  The stream and its sidecar are the record. A writer creates both with mode 0640
  and never in a directory another uid owns (F-021). A checkpoint names how many
  lines a stream held, the chain hash of the last, and the SHA-256 of every byte
  through them, and it is signed. The bytes are the RFC 8785 serialization of the
  record, so every implementation that agrees on the members writes the same bytes
  (SPEC 6.5.1, format v1). The vendored vectors are that agreement, and the
  scenarios below hold this module to them and to the refusals v1 requires.

  @decided 2026-10-18: the sidecar is written and verified to the byte, and an
  earlier byte rewritten after a checkpoint is refused by that checkpoint. A
  checkpoint binds the bytes through its count, not the history before the first
  record a verifier keeps.

  # @test:TestNewWriterCreatesTheStreamMode0640
  Scenario: A plain writer creates its stream mode 0640
    Given a directory this process owns and no stream in it
    When a plain writer appends one event
    Then the stream exists with mode 0640

  # @test:TestNewChainedWriterCreatesTheStreamMode0640
  Scenario: A chained writer creates its stream mode 0640
    Given a directory this process owns and no stream in it
    When a chained writer appends one event
    Then the stream exists with mode 0640

  # @test:TestAWriterCreatesNoFileInADirectoryItDoesNotOwn
  Scenario: No writer creates a stream in a directory it does not own
    Given a directory that belongs to another uid
    When a plain writer and a chained writer are each asked to create a stream there
    Then both are refused and no file appears

  # @test:TestACheckpointIsNotCreatedInADirectoryItDoesNotOwn
  Scenario: No checkpoint sidecar is created in a directory it does not own
    Given a checkpoints directory that belongs to another uid
    When a checkpointing writer is opened on a stream
    Then it is refused and no sidecar appears

  # @test:TestAWriterStillAppendsToAnExistingStreamInAForeignDirectory
  Scenario: An existing stream is appended to even where its directory is not owned
    Given a stream that already exists in a directory another uid owns
    When a chained writer appends an event to it
    Then the event is written and the stream is not re-moded

  # @test:TestTheSidecarIsCreatedMode0640
  Scenario: The checkpoint sidecar is created mode 0640
    Given a checkpointing writer in a directory this process owns
    When it writes its first checkpoint
    Then the sidecar exists with mode 0640

  # @test:TestACheckpointIsWrittenEverySixtyFourEvents
  Scenario: A checkpoint is written every sixty-four events
    Given a checkpointing writer that is never idle
    When it writes sixty-four events
    Then the sidecar holds a checkpoint over sixty-four lines

  # @test:TestACheckpointIsWrittenAfterTenSecondsEvenBelowSixtyFourEvents
  Scenario: A checkpoint is written after ten seconds
    Given a checkpointing writer that has written one event
    When ten seconds pass and it writes one more
    Then the sidecar holds a checkpoint over both lines

  # @test:TestACloseWritesACloseRecordForTheWholeStream
  Scenario: Closing writes a close record over the whole stream
    Given a checkpointing writer that has written five events
    When it is closed
    Then the last record is a close over five lines, and it verifies

  # @test:TestEveryRecordsPrefixIsTheStreamBytesThroughItsCount
  Scenario: Every prefix is the stream's bytes through its count
    Given a checkpointing writer that writes every two lines
    When it writes seven events and is closed
    Then every record verifies against the stream as written

  # @test:TestTwoWritersOnOneStreamKeepOneHonestPrefix
  Scenario: A prefix covers lines another writer appended
    Given a checkpointing writer and a plain chained writer sharing one stream
    When both write and the checkpointing writer checkpoints
    Then every record it wrote verifies, because its prefix hashed the other writer's lines

  # @test:TestAnExpiredKeyWritesAnUnsignedRecordThatIsNotValid
  Scenario: An expired key writes an unsigned record, which is never reported valid
    Given a checkpointing writer whose key has expired
    When it writes a checkpoint
    Then the record carries unsigned_reason key_expired and no signature, and it is reported unsigned

  # @test:TestASignerFailureWritesNoRecordAndSaysSo
  Scenario: A failed signature writes no record and returns the failure
    Given a checkpointing writer whose signer fails for a reason other than expiry
    When it writes an event
    Then the event is on disk, no record is written, and the failure is returned

  # @test:TestAResumeRecordNamesTheLastWellFormedEvent
  Scenario: A writer that reopens a fragmented tail names the last good event
    Given a stream whose last line is not an event
    When a checkpointing writer opens it
    Then it writes a resume record naming the last well-formed line, and the record verifies

  # @test:TestNoResumeRecordWhenTheTailChains
  Scenario: A writer that reopens a chainable tail writes no resume record
    Given a stream whose last line is an event
    When a checkpointing writer opens it
    Then no resume record is written

  # @test:TestTheEncoderReproducesEveryVendoredRecordByteForByte
  Scenario: The encoder writes every vendored record byte for byte
    Given the vendored checkpoint vectors
    When each record is encoded from its members with the vector's signature
    Then the signing input and the record are identical to the vector's bytes

  # @test:TestTheVendoredRecordsVerifyOnTheirStream
  Scenario: Every vendored record verifies on its stream
    Given the vendored vectors' stream and sidecar
    When the sidecar is verified against the stream
    Then the signed records are valid and the unsigned one is unsigned

  # @test:TestTheVendoredNegativeVariantsAreRefusedExactlyAsNamed
  Scenario: The vendored negative variants are refused exactly as they name
    Given the forged-prefix, prefix-only and truncated variants, each passing the chain on its own
    When the sidecar is verified against each
    Then exactly the records each names are refused, for the reason each names

  # @test:TestVerifyCheckpointsAcceptsARecordThatIsRightInEveryMember
  Scenario: A record right in every member verifies
    Given a record written by the encoder over a stream
    When the sidecar is verified against that stream
    Then the record is valid

  # @test:TestVerifyCheckpointsRefusesABadSignature
  Scenario: A changed signature byte is refused
    Given a signed record with one byte of its signature changed
    When it is verified
    Then it is refused as a bad signature

  # @test:TestVerifyCheckpointsRefusesAHeadThatNamesAnotherLine
  Scenario: A head naming another line is refused even when correctly signed
    Given a record signed over a head that names another line
    When it is verified
    Then it is refused as a head that does not equal the chain hash of its line

  # @test:TestVerifyCheckpointsRefusesAPrefixOfOtherBytes
  Scenario: A prefix of other bytes is refused even when correctly signed
    Given a record signed over the prefix of a different count
    When it is verified
    Then it is refused as a prefix that does not match

  # @test:TestVerifyCheckpointsRefusesAPrevThatDoesNotChain
  Scenario: A prev that does not chain from the record before is refused
    Given a second record whose prev is not the hash of the first
    When the sidecar is verified
    Then the second record is refused as a prev that does not chain

  # @test:TestVerifyCheckpointsRefusesARecordThatIsNotItsOwnCanonicalBytes
  Scenario: A record that is not its own canonical bytes is refused
    Given a record with the same members in another order
    When it is verified
    Then it is refused as not the canonical serialization

  # @test:TestVerifyCheckpointsRefusesAnotherStreamsRecord
  Scenario: A record naming another stream is refused
    Given a record whose stream member names another file
    When it is verified
    Then it is refused as naming another stream

  # @test:TestVerifyCheckpointsRefusesAnUnknownKid
  Scenario: A record under a key the verifier does not hold is refused
    Given a record signed by a key the verifier was not given
    When it is verified
    Then it is refused as under a key the verifier does not hold

  # @test:TestVerifyCheckpointsReportsATruncatedStream
  Scenario: A stream shorter than a record counts is reported as a truncation
    Given a record counting three lines and a stream of two
    When it is verified
    Then it is refused as a truncation

  # @test:TestVerifyCheckpointsIgnoresATornFinalLine
  Scenario: A torn final line is not a record
    Given a sidecar whose last line has no newline
    When it is verified
    Then the complete records are judged and the torn line is ignored

  # @test:TestVerifyCheckpointsOfAnEmptySidecarMeasuredNothing
  Scenario: A sidecar with no record is measured nothing, not a pass
    Given an empty sidecar
    When it is verified
    Then the verifier says nothing was measured

  # @test:TestAnUnsignedRecordWithAnotherReasonIsRefused
  Scenario: An unsigned record with any reason but key_expired is refused
    Given an unsigned record whose unsigned_reason is not key_expired
    When it is verified
    Then it is refused

  # @test:TestVerifyChainReportsTheLastWellFormedLineBeforeEachRestart
  Scenario: Each restart names the last well-formed line before it
    Given a stream that restarts after a malformed line and straight after a good line
    When it is verified for restarts
    Then each restart is reported with the line before it, and no restart is a break
