#  Copyright (c) 2020. Sophos Limited
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import intelix_file_check
import os


# TODO: Add CI stuff for GitLab


def test_login():
    intelix_file_check.access_token = ""

    intelix_file_check.login()

    assert intelix_file_check.access_token != ""


def test_login_token_exists():
    intelix_file_check.login()
    current_token = intelix_file_check.access_token

    intelix_file_check.login()

    assert intelix_file_check.access_token == current_token


def test_cloud_lookup_malware():
    file_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # EICAR

    score = intelix_file_check.cloud_lookup(file_hash)

    assert score < 20


def test_cloud_lookup_clean():
    file_hash = "f2d2638afb528c7476c9ee8e83ddb20e686b0b05f53f2f966fd9eb962427f8aa"  # Putty

    score = intelix_file_check.cloud_lookup(file_hash)

    assert score > 70


def test_cloud_lookup_unknown():
    file_hash = "774d30c96ff52a1b669956a5f5e38722d181c7698a4fbb5c34e2dbf10a9f8fa5"  # test.rtf

    score = intelix_file_check.cloud_lookup(file_hash)

    assert score > 19
    assert score < 70


def test_static_analysis():
    filename = "test.rtf"

    score = intelix_file_check.static_analysis(filename)

    assert score > 19


def test_dynamic_analysis():
    filename = "test.rtf"

    score = intelix_file_check.dynamic_analysis(filename)

    assert score > 19


def test_complete_check_for_malware():
    filename = "test.rtf"

    is_malware = intelix_file_check.complete_check_for_malware(filename)

    assert not is_malware
