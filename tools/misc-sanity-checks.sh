#! /bin/sh
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

TMPDIR=`mktemp -d /tmp/${0##*/}.XXXXXX` || exit 1
export TMPDIR
trap "rm -rf $TMPDIR" EXIT

FAILURES=$TMPDIR/failures

check_no_duplicate_api_test_idempotent_ids() {
    # For API tests, an idempotent ID is assigned to each single API test,
    # those IDs should be unique
    output=$(check-uuid --package neutron_tempest_plugin)
    if [ "$?" -ne 0 ]; then
        echo "There are duplicate idempotent ids in the API tests" >>$FAILURES
        echo "please, assign unique uuids to each API test:" >>$FAILURES
        echo "$output" >>$FAILURES
    fi
}

check_no_duplicate_api_test_idempotent_ids

# Fail, if there are emitted failures
if [ -f $FAILURES ]; then
    cat $FAILURES
    exit 1
fi
