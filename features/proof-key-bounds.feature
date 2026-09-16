Feature: A key's size is bounded before any arithmetic is done with it

  A DPoP proof carries its own public key, and the issuer's token door checks
  the proof before it authenticates anything else, so the work of refusing a
  proof is work anybody who can reach the door may order. The exponent has had
  a bound since this package was written; the modulus had none, and the
  standard library bounds a modulus from below only. Measured 2026-09-16 with
  rsa.VerifyPKCS1v15 on Apple silicon, an all-ones modulus of 48 KiB, the
  widest that fits under vouchryx's 64 KiB body cap, cost 1.34 seconds of one
  core against 245 microseconds for a 2048-bit key.

  @decided 2026-09-16: bound the modulus, red first, and prove the bound at
  both the key and the door.

  # @test:TestAnAbsurdRsaModulusIsRefusedRatherThanComputed
  Scenario: The widest key anybody issues still fits, and one byte more does not
    Given an RSA modulus of exactly 8192 bits
    And one a single byte wider
    When each is read as a public key
    Then the first is accepted and the second is refused

  # @test:TestAProofCarryingAnOversizedRsaKeyIsRefusedBeforeAnyArithmetic
  Scenario: An oversized key in a proof is refused at the door, not after the exponentiation
    Given a proof whose header carries a 48 KiB RSA modulus and a signature to match
    When the verifier checks it
    Then it is refused in the time it takes to read the header, never in the time it takes to exponentiate
