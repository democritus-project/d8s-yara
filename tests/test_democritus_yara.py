"""Tests for `democritus_yara` module."""

import plyara
import pytest

from democritus_yara import (
    is_yara_rule,
    yara_rules_find,
    yara_rules_standardize,
    yara_rules_parse,
    yara_rules_names,
    yara_rules_tags,
    yara_rules_strings,
    yara_rules_metadata,
)


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


def test_yara_rules_find_1():
    results = yara_rules_find(SIMPLE_RULE_1)
    assert results == ['rule MyRule { strings: $a="1" condition: false }']

    results = yara_rules_find(COMPLEX_RULE_1)
    assert len(results) == 1


def test_yara_rules_standardize_1():
    standardized_rule = yara_rules_standardize(SIMPLE_RULE_1)
    assert isinstance(standardized_rule, list)
    assert standardized_rule[0] == 'rule MyRule {\n\n\tstrings:\n\t\t$a = "1"\n\n\tcondition:\n\t\tfalse\n}\n'


def test_multiple_rules_yara_rules_parse_1():
    s = SIMPLE_RULE_1 + '\n\n' + COMPLEX_RULE_1
    results = yara_rules_parse(s)
    assert len(results) == 2


def test_invalid_yara_rules_parse():
    # try to parse an incomplete yara rule
    with pytest.raises(plyara.exceptions.ParseTypeError):
        yara_rules_parse(SIMPLE_RULE_1[5:])


def test_yara_rules_parse_1():
    results = yara_rules_parse(SIMPLE_RULE_1)
    assert isinstance(results, list)
    assert isinstance(results[0], dict)
    assert results[0]['rule_name'] == 'MyRule'

    results = yara_rules_parse(COMPLEX_RULE_1)
    assert isinstance(results, list)
    assert isinstance(results[0], dict)
    assert results[0]['rule_name'] == 'silent_banker'


def test_yara_rules_names_1():
    assert yara_rules_names(SIMPLE_RULE_1) == ['MyRule']
    assert yara_rules_names(COMPLEX_RULE_1) == ['silent_banker']


def test_yara_rules_tags_1():
    assert yara_rules_tags(SIMPLE_RULE_1) == []
    assert yara_rules_tags(COMPLEX_RULE_1) == [['banker']]


def test_yara_rules_strings_1():
    assert yara_rules_strings(SIMPLE_RULE_1) == [[{'name': '$a', 'value': '1', 'type': 'text'}]]
    assert yara_rules_strings(COMPLEX_RULE_1) == [
        [
            {'name': '$a', 'value': '{6A 40 68 00 30 00 00 6A 14 8D 91}', 'type': 'byte'},
            {'name': '$b', 'value': '{8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}', 'type': 'byte'},
            {'name': '$c', 'value': 'UVODFRYSIHLNWPEJXQZAKCBGMT', 'type': 'text'},
        ]
    ]


def test_yara_rules_metadata_1():
    assert yara_rules_metadata(SIMPLE_RULE_1) == []
    assert yara_rules_metadata(COMPLEX_RULE_1) == [
        [{'description': 'This is just an example'}, {'thread_level': 3}, {'in_the_wild': True}]
    ]
