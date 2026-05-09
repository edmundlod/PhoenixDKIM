# opendkim Integration Tests

This directory contains integration tests for the opendkim filter daemon.
Tests are written in Lua and executed via the `miltertest` tool.

## Running

Tests are registered with CTest and run automatically as part of the
standard test suite:

```
ctest --test-dir build
```

To run only the opendkim integration tests:

```
ctest --test-dir build -R t-
```

## Writing Tests

Each test is a Lua script that uses the `miltertest` API to simulate an
MTA–milter conversation. See `miltertest/miltertest.8` for the full API
reference and `miltertest/README.md` for an overview.

Test scripts in this directory follow the naming convention `t-<name>.lua`.
A shared setup fixture (`t-setup.lua`) and cleanup fixture (`t-cleanup.lua`)
run before and after the test suite respectively.
