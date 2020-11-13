"""Democritus module to work with YARA rules."""

from typing import List

from .yara_grammars import yara_rule_grammar


def is_yara_rule(possible_yara_rule: str) -> bool:
    """Check if the possible_yara_rule is a yara rule."""
    yara_rules = yara_rules_find(possible_yara_rule)
    print('yara_rules {}'.format(yara_rules))

    if len(yara_rules) == 1:
        return True
    return False


def yara_rules_find(text: str) -> List[str]:
    """Parse yara rules from the given text."""
    yara_rules = yara_rule_grammar.searchString(text).asList()
    stringified_yara_rules = []

    for rule in yara_rules:
        yara_rule_string = ' '.join(rule)
        stringified_yara_rules.append(yara_rule_string)

    return stringified_yara_rules
