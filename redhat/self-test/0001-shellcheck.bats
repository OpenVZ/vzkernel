@test "shellcheck" {
      run shellcheck $(find $BATS_TEST_DIRNAME/.. -name "*.sh")
      [ "$status" = 0 ]
}
