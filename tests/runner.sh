#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Eugen Kremer <eugen.kremer@siemens.com>
#
#

if [ $# -eq 1 ];  then
    #delete on exit
    trap 'rm -f  /tmp/runner-test-result.txt' EXIT

    SCRIPT_NAME="$(basename "$1" .sh)"

    if [ -z "$SUPPRESS_OUTPUT" ]; then
        $1 2>&1
    else
        $1 > /tmp/runner-test-result.txt 2>&1
    fi;

    if [ $? -gt 0 ]; then
        echo $SCRIPT_NAME - FAILED
        if [ ! -z "$SUPPRESS_OUTPUT" ]; then
            printf "\033[31m"
            sed 's/^/    /' /tmp/runner-test-result.txt
            printf "\033[0m"
        fi;
        exit 1
    else
        echo $SCRIPT_NAME - SUCCEEDED
        exit 0
    fi;
else
    #delete on exit
    trap 'rm -f testresult.txt' EXIT
    
    echo Run all tests

    export SUPPRESS_OUTPUT=1

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    find $SCRIPT_DIR -name "test_*.sh" | sort | xargs -i $0 "{}" | tee testresult.txt
    failed=$(cat testresult.txt|grep " - FAILED"|wc -l)

    if [ $failed -gt 0 ]; then
        echo "Failed $failed test(s)"
        exit $failed
    fi;
fi;
