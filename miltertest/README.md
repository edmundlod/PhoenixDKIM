# miltertest

`miltertest` is a testing tool that simulates the MTA side of an
MTA–milter conversation. It takes a Lua script as input and drives a
milter-aware filter through a complete SMTP transaction, making it
straightforward to write integration tests for milter filters.

## Building

miltertest requires Lua 5.4. Enable it at CMake configure time:

```
cmake -B build -DWITH_LUA=ON
cmake --build build
```

The resulting binary is `build/miltertest/miltertest`.

## Usage

```
miltertest [-D name[=value]] [-s script] [-u] [-v] [-w]
```

| Flag | Description |
|---|---|
| `-D name[=value]` | Define a Lua global variable |
| `-s script` | Lua script file to execute (default: stdin) |
| `-u` | Report user/system time after the filter exits |
| `-v` | Increase verbosity (may be repeated) |
| `-w` | Tolerate filter startup delay |

See `miltertest(8)` for the full option reference and the complete list
of Lua functions provided by miltertest.

## Writing Tests

A miltertest script drives a filter through an SMTP transaction using
functions exported into the Lua environment. A minimal test looks like:

```lua
-- start the filter
local mt = MT.startfilter("opendkim", "-x", "/etc/opendkim/opendkim.conf")
if mt == nil then
    error("failed to start filter")
end

-- connect and run a message through
MT.connect("localhost", false, "127.0.0.1")
MT.helo("localhost")
MT.mailfrom("sender@example.com")
MT.rcptto("recipient@example.com")
MT.header("From", "sender@example.com")
MT.header("To", "recipient@example.com")
MT.header("Subject", "Test message")
MT.eoh()
MT.bodystring("This is the message body.\r\n")
MT.eom()
MT.disconnect()
MT.stopfilter(mt)
```

Any step prior to end-of-message that is omitted is filled in with
legal placeholder data automatically.

## Integration with CTest

The opendkim integration tests in `opendkim/tests/` use miltertest and
are registered with CTest. Run them with:

```
ctest --test-dir build -R t-
```
