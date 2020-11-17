"""Democritus module to work with YARA rules."""

from typing import List, Dict, Any

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


def yara_rules_standardize(yara_rules_string: str) -> List[str]:
    """Standardize the given yara rule(s)."""
    yara_rules_data = yara_rules_parse(yara_rules_string)
    parser = _plyara_parser()
    rebuilt_rules = []

    for rule in yara_rules_data:
        rebuilt_rule = parser.rebuild_yara_rule(rule)
        rebuilt_rules.append(rebuilt_rule)

    return rebuilt_rules


def _plyara_parser():
    """Return an instance of a plyara parser."""
    import plyara

    # TODO: with the current structure of this module, I'm going to have to reinitialize a plyara parser every time I call one of the functions that uses the parser... I would like to find a better way to do this
    parser = plyara.Plyara()
    return parser


def yara_rules_parse(yara_rules_string: str) -> List[List[Dict[str, Any]]]:
    """Parse the given yara_rule string using plyara (see https://plyara.readthedocs.io/en/latest/)."""
    parser = _plyara_parser()
    try:
        parser.parse_string(yara_rules_string)
    except Exception:
        message = 'The given text is not a valid yara rule.'
        raise

    return parser.rules


# TODO: write and use a decorator that parses a yara rule
def yara_rules_names(yara_rules_string: str) -> List[str]:
    """Get the name(s) of the given yara_rule(s)."""
    yara_rules_data = yara_rules_parse(yara_rules_string)
    all_rule_names = []

    for rule in yara_rules_data:
        if rule.get('rule_name'):
            rule_name = rule['rule_name']
            all_rule_names.append(rule_name)

    return all_rule_names


def yara_rules_tags(yara_rules_string: str) -> List[str]:
    """Get the tags for the given yara_rule(s)."""
    yara_rules_data = yara_rules_parse(yara_rules_string)
    all_rule_tags = []

    for rule in yara_rules_data:
        if rule.get('tags'):
            rule_tags = rule['tags']
            all_rule_tags.append(rule_tags)

    return all_rule_tags


def yara_rules_strings(yara_rules_string: str) -> List[List[Dict[str, Any]]]:
    """Get the strings used in the given yara_rule(s)."""
    yara_rules_data = yara_rules_parse(yara_rules_string)
    all_rule_strings = []

    for rule in yara_rules_data:
        if rule.get('strings'):
            yara_rule_strings = rule['strings']
            all_rule_strings.append(yara_rule_strings)

    return all_rule_strings


def yara_rules_metadata(yara_rules_string: str) -> List[List[Dict[str, Any]]]:
    """Get the metadata for the given yara_rule(s)."""
    yara_rules_data = yara_rules_parse(yara_rules_string)
    all_rule_metadata = []

    for rule in yara_rules_data:
        if rule.get('metadata'):
            yara_rule_metadata = rule['metadata']
            all_rule_metadata.append(yara_rule_metadata)

    return all_rule_metadata
