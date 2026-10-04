Feature: The chain verifier is a published image a launcher can schedule

  `agent-conform` existed only as source and as per-platform archives, so
  nothing on a box that runs the stack could verify the shared events bus on a
  schedule. A container image is the shape a CronJob or a compose service
  takes, and it is published the way the archives already are: by a version tag,
  signed keyless, with a provenance attestation.

  Nothing about publishing runs before a tag, which is the usual way such a job
  fails for the first time in public. The image build also runs on a pull
  request that touches the Dockerfile or the workflow, and that build pushes
  nothing.

  # @test:TestTheImageJobPublishesOnATagOnlyAndSignsWhatItPublishes
  Scenario: A version tag publishes a signed, attested, two-architecture image
    Given the release workflow
    When a v* tag is pushed
    Then it publishes ghcr.io/taipanbox/agent-conform for amd64 and arm64
    And the image is signed by digest and its provenance attested
    And no moving tag such as latest is published

  # @test:TestTheImageJobPublishesOnATagOnlyAndSignsWhatItPublishes
  Scenario: A pull request builds the image and publishes nothing
    Given a pull request that changes the Dockerfile or the release workflow
    When the workflow runs
    Then the image is built without being pushed
    And the job that pushes is guarded off that event by name

  # @test:TestTheDockerfileIsStaticNonRootAndNamesTheCommand
  Scenario: The image is static, non-root and pinned
    Given the Dockerfile
    When it is read
    Then it builds agent-conform with cgo off, runs as a numeric non-root user,
      and takes its runtime base by digest
