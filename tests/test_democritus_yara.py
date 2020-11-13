#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for `democritus_yara` module."""

import pytest

from democritus_yara import is_yara_rule


SIMPLE_RULE_1 = 'rule MyRule { strings: $a="1" \n condition: false }'
COMPLEX_RULE_1 = '''rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        thread_level = 3
        in_the_wild = true
    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
    condition:
        $a or $b or $c
}
'''


def test_is_yara_rule_docs_1():
    assert is_yara_rule(SIMPLE_RULE_1)
    assert is_yara_rule(COMPLEX_RULE_1)
    assert not is_yara_rule('foo bar')
