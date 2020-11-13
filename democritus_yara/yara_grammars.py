from pyparsing import OneOrMore, Or, Word, Optional, alphas, alphanums, printables

yara_rule_scopes_list = ['private', 'global']
yara_rule_scopes = OneOrMore(Or(yara_rule_scopes_list))
# yara rule names are alphanumeric with '_' and cannot start with a number
yara_rule_name = Word(alphas + '_', bodyChars=alphanums + '_')
# yara rule tags have the same stipulations as the yara rule names (alphanumeric with underscores (see: https://yara.readthedocs.io/en/latest/writingrules.html#rule-tags))
yara_rule_tags = OneOrMore(yara_rule_name)
yara_rule_prefix = (
    Optional(yara_rule_scopes)('yara_rule_scopes')
    + Word('rule')
    + yara_rule_name('yara_rule_name')
    + Optional(Word(':') + yara_rule_tags)
)
# for the rule body, find any printable character and make sure the last character is a '}' representing the end of the yara rule
rule_body = OneOrMore(
    Word(printables).addCondition(lambda tokens: tokens[0] != 'rule' and tokens[0] not in yara_rule_scopes_list)
).addCondition(lambda tokens: tokens[-1] == '}')
yara_rule_grammar = yara_rule_prefix + '{' + rule_body
