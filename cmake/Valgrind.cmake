# cmake/Valgrind.cmake
#
# Valgrind Memcheck and Helgrind integration for PhoenixDKIM.
#
# Options
# -------
#   OPENDKIM_ENABLE_VALGRIND   ON → Memcheck (heap/uninit/leak)
#   OPENDKIM_ENABLE_HELGRIND   ON → Helgrind (thread-race detector)
#
# Both options do two things:
#
#   1. Configure MEMORYCHECK_COMMAND / MEMORYCHECK_COMMAND_OPTIONS so that
#      "ctest -T memcheck" instruments the libphoenixdkim unit-test binaries
#      directly through Valgrind.
#
#   2. Generate a thin shell wrapper
#         ${CMAKE_BINARY_DIR}/valgrind-bin/phoenixdkim
#      and set OPENDKIM_VALGRIND_BIN_DIR so that phoenixdkim/tests/CMakeLists.txt
#      can point PHOENIXDKIM_BINPATH there.  The miltertest Lua scripts call
#         binpath .. "/phoenixdkim"
#      so the daemon itself then runs under Valgrind without touching the
#      Lua scripts at all.
#
# IMPORTANT: do NOT combine either option with OPENDKIM_ENABLE_ASAN,
# OPENDKIM_ENABLE_UBSAN, OPENDKIM_ENABLE_LSAN, or OPENDKIM_ENABLE_MSAN.
# ASan's shadow-memory layout is incompatible with Valgrind's instrumentation
# and the process will crash at startup.
#
# Recommended build directories:
#   build-valgrind/  — cmake -DOPENDKIM_ENABLE_VALGRIND=ON  -DCMAKE_BUILD_TYPE=Debug ...
#   build-helgrind/  — cmake -DOPENDKIM_ENABLE_HELGRIND=ON  -DCMAKE_BUILD_TYPE=Debug ...

# ── Options ───────────────────────────────────────────────────────────────────

option(OPENDKIM_ENABLE_VALGRIND
    "Run tests under Valgrind Memcheck: uninitialised reads, heap errors, leaks. \
Mutually exclusive with ASan/UBSan/MSan and with HELGRIND. Use a plain Debug build."
    OFF)

option(OPENDKIM_ENABLE_HELGRIND
    "Run tests under Valgrind Helgrind: thread-race and lock-order detection. \
Mutually exclusive with ASan/UBSan/MSan and with VALGRIND. Use a plain Debug build."
    OFF)

# ── Mutual-exclusion checks ────────────────────────────────────────────────────

if(OPENDKIM_ENABLE_VALGRIND AND OPENDKIM_ENABLE_HELGRIND)
    message(FATAL_ERROR
        "OPENDKIM_ENABLE_VALGRIND and OPENDKIM_ENABLE_HELGRIND cannot both be ON: "
        "they select different Valgrind tools (memcheck vs helgrind). "
        "Use two separate build directories if you want to run both.")
endif()

foreach(_san IN ITEMS
        OPENDKIM_ENABLE_ASAN OPENDKIM_ENABLE_UBSAN
        OPENDKIM_ENABLE_LSAN OPENDKIM_ENABLE_MSAN)
    if((OPENDKIM_ENABLE_VALGRIND OR OPENDKIM_ENABLE_HELGRIND) AND ${_san})
        message(FATAL_ERROR
            "${_san} and Valgrind are mutually exclusive. "
            "ASan/UBSan shadow memory conflicts with Valgrind's instrumentation "
            "and will crash at startup. "
            "Configure a sanitizer-free Debug build for Valgrind/Helgrind.")
    endif()
endforeach()

# ── Bail early when neither tool is requested ──────────────────────────────────

if(NOT OPENDKIM_ENABLE_VALGRIND AND NOT OPENDKIM_ENABLE_HELGRIND)
    return()
endif()

# ── Find valgrind ──────────────────────────────────────────────────────────────

find_program(VALGRIND_EXECUTABLE valgrind
    DOC "Valgrind dynamic-analysis tool (memcheck / helgrind)")

if(NOT VALGRIND_EXECUTABLE)
    message(FATAL_ERROR
        "Valgrind was not found on PATH. "
        "Install it (e.g. 'dnf install valgrind') or set VALGRIND_EXECUTABLE "
        "to its full path, then re-run cmake.")
endif()

# ── Choose tool and build option list ─────────────────────────────────────────

set(_supp_file "${CMAKE_SOURCE_DIR}/cmake/valgrind.supp")

if(OPENDKIM_ENABLE_VALGRIND)
    set(_vg_tool "memcheck")
    set(_vg_opts
        --tool=memcheck
        --track-origins=yes
        --error-exitcode=1
        --leak-check=full
        --show-leak-kinds=definite,indirect
        --errors-for-leak-kinds=definite,indirect
        --num-callers=30
    )
elseif(OPENDKIM_ENABLE_HELGRIND)
    set(_vg_tool "helgrind")
    set(_vg_opts
        --tool=helgrind
        --error-exitcode=1
        --num-callers=30
    )
endif()

if(EXISTS "${_supp_file}")
    list(APPEND _vg_opts "--suppressions=${_supp_file}")
endif()

# ── Configure CTest memcheck (unit tests) ─────────────────────────────────────
# "ctest -T memcheck" prepends MEMORYCHECK_COMMAND + MEMORYCHECK_COMMAND_OPTIONS
# to each test's command line.  This is ideal for unit-test binaries that run
# directly.  Integration tests (miltertest) are handled separately via the
# wrapper script below.

list(JOIN _vg_opts " " _vg_opts_str)

set(MEMORYCHECK_COMMAND          "${VALGRIND_EXECUTABLE}"  CACHE FILEPATH "" FORCE)
set(MEMORYCHECK_TYPE             "Valgrind"                CACHE STRING   "" FORCE)
set(MEMORYCHECK_COMMAND_OPTIONS  "${_vg_opts_str}"         CACHE STRING   "" FORCE)
if(EXISTS "${_supp_file}")
    set(MEMORYCHECK_SUPPRESSIONS_FILE "${_supp_file}"      CACHE FILEPATH "" FORCE)
endif()

# ── Generate integration-test wrapper script ──────────────────────────────────
# The Lua test drivers call:
#   os.getenv("PHOENIXDKIM_BINPATH") .. "/phoenixdkim"
# We generate a wrapper script at that path that execs the real daemon under
# Valgrind, so the daemon is instrumented even though miltertest itself is not.

set(OPENDKIM_VALGRIND_BIN_DIR "${CMAKE_BINARY_DIR}/valgrind-bin")
set(_real_bin                 "${CMAKE_BINARY_DIR}/phoenixdkim/phoenixdkim")

# Build a properly-quoted exec line for the shell wrapper.
# Each argument goes on its own line for readability.
set(_exec_line "\"${VALGRIND_EXECUTABLE}\"")
foreach(_opt IN LISTS _vg_opts)
    string(APPEND _exec_line " \\\n    \"${_opt}\"")
endforeach()
string(APPEND _exec_line " \\\n    \"${_real_bin}\"")

# Write the wrapper.  configure_file runs at configure time; the generated
# file lives inside the build tree so it is never tracked by git.
set(VALGRIND_WRAPPER_EXEC_LINE "${_exec_line}")
set(VALGRIND_TOOL_NAME         "${_vg_tool}")

file(MAKE_DIRECTORY "${OPENDKIM_VALGRIND_BIN_DIR}")
configure_file(
    "${CMAKE_SOURCE_DIR}/cmake/valgrind-wrapper.sh.in"
    "${OPENDKIM_VALGRIND_BIN_DIR}/phoenixdkim"
    @ONLY
)
file(CHMOD "${OPENDKIM_VALGRIND_BIN_DIR}/phoenixdkim"
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

message(STATUS
    "Valgrind ${_vg_tool}: integration-test wrapper → "
    "${OPENDKIM_VALGRIND_BIN_DIR}/phoenixdkim")
