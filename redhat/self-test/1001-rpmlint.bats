#!/usr/bin/env bats
@test "Exactly one SRPM exists" {
    result=$(find "$BATS_TEST_DIRNAME"/.. -name "*.rpm" | wc -l)
    [ "$result" = 1 ]
}

@test "rpmlint" {
      srpm=$(find "$BATS_TEST_DIRNAME"/.. -name "*.rpm")
      run rpmlint $srpm
      [ "$status" = 0 ]
}
