"""Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

from cryptojwt.utils import as_bytes, as_unicode

"""Test utilities."""

__author__ = 'quannguyen@google.com (Quan Nguyen)'

from cryptojwt import utils


def modify_token(token):
    parts = token.split('.')
    assert (len(parts) == 3)
    for i in range(len(parts)):
        modified_parts = parts[:]
        decoded_part = utils.b64d(as_bytes(modified_parts[i]))
        for s in modify_str(as_unicode(decoded_part)):
            modified_parts[i] = utils.b64e(s)
            yield (modified_parts[0] + b'.' + modified_parts[1] + b'.' +
                   modified_parts[2])


def modify_str(s):
    # Modify each bit of string.
    for i in range(len(s)):
        c = s[i]
        for j in range(8):
            c = chr(ord(c) ^ (1 << j))
        s[i] = c

    # Truncate string.
    for i in range(len(s)):
        yield s[:i]
