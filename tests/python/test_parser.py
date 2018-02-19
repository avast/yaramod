import unittest
import yaramod


class ParserTests(unittest.TestCase):
    def test_empty_input(self):
        yara_file = yaramod.parse_string('')

        self.assertEqual(yara_file.text, '')

    def test_empty_rule(self):
        yara_file = yaramod.parse_string('''
rule empty_rule {
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'empty_rule')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(len(rule.metas), 0)
        self.assertEqual(len(rule.strings), 0)
        self.assertEqual(len(rule.tags), 0)

    def test_rule_with_tags(self):
        yara_file = yaramod.parse_string('''
rule rule_with_tags : Tag1 Tag2 Tag3 {
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'rule_with_tags')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(len(rule.metas), 0)
        self.assertEqual(len(rule.strings), 0)
        self.assertListEqual(rule.tags, ['Tag1', 'Tag2', 'Tag3'])

    def test_rule_with_metas(self):
        yara_file = yaramod.parse_string('''
rule rule_with_metas {
    meta:
        str_meta = "string meta"
        int_meta = 42
        bool_meta = true
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'rule_with_metas')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(len(rule.metas), 3)
        self.assertEqual(len(rule.strings), 0)
        self.assertEqual(len(rule.tags), 0)

        self.assertEqual(rule.metas[0].key, 'str_meta')
        self.assertTrue(rule.metas[0].value.is_string)
        self.assertEqual(rule.metas[0].value.text, '"string meta"')
        self.assertEqual(rule.metas[0].value.pure_text, 'string meta')

        self.assertEqual(rule.metas[1].key, 'int_meta')
        self.assertTrue(rule.metas[1].value.is_int)
        self.assertEqual(rule.metas[1].value.text, '42')

        self.assertEqual(rule.metas[2].key, 'bool_meta')
        self.assertTrue(rule.metas[2].value.is_bool)
        self.assertEqual(rule.metas[2].value.text, 'true')

    def test_rule_with_plain_strings(self):
        yara_file = yaramod.parse_string('''
rule rule_with_plain_strings {
    strings:
        $1 = "Hello World!"
        $2 = "Bye World."
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'rule_with_plain_strings')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(len(rule.metas), 0)
        self.assertEqual(len(rule.strings), 2)
        self.assertEqual(len(rule.tags), 0)

        hello_world = rule.strings[0]
        self.assertEqual(hello_world.identifier, '$1')
        self.assertEqual(hello_world.text, '"Hello World!"')
        self.assertEqual(hello_world.pure_text, 'Hello World!')
        self.assertTrue(hello_world.is_ascii)

        bye_world = rule.strings[1]
        self.assertEqual(bye_world.identifier, '$2')
        self.assertEqual(bye_world.text, '"Bye World."')
        self.assertEqual(bye_world.pure_text, 'Bye World.')
        self.assertTrue(bye_world.is_ascii)

    def test_multiple_rules(self):
        yara_file = yaramod.parse_string('''
rule rule_1 {
    strings:
        $1 = "String from Rule 1"
    condition:
        true
}

rule rule_2 {
    strings:
        $1 = "String from Rule 2"
    condition:
        true
}

rule rule_3 {
    strings:
        $1 = "String from Rule 3"
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 3)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'rule_1')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(rule.strings[0].identifier, '$1')
        self.assertEqual(rule.strings[0].pure_text, 'String from Rule 1')

        rule = yara_file.rules[1]
        self.assertEqual(rule.name, 'rule_2')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(rule.strings[0].identifier, '$1')
        self.assertEqual(rule.strings[0].pure_text, 'String from Rule 2')

        rule = yara_file.rules[2]
        self.assertEqual(rule.name, 'rule_3')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(rule.strings[0].identifier, '$1')
        self.assertEqual(rule.strings[0].pure_text, 'String from Rule 3')

    def test_plain_strings_with_modifiers(self):
        yara_file = yaramod.parse_string('''
rule rule_with_plain_strings_with_modifiers {
    strings:
        $1 = "Hello World!" nocase wide
        $2 = "Bye World." fullword
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'rule_with_plain_strings_with_modifiers')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(len(rule.strings), 2)

        string = rule.strings[0]
        self.assertFalse(string.is_ascii)
        self.assertTrue(string.is_wide)
        self.assertTrue(string.is_nocase)
        self.assertFalse(string.is_fullword)

        string = rule.strings[1]
        self.assertTrue(string.is_ascii)
        self.assertFalse(string.is_wide)
        self.assertFalse(string.is_nocase)
        self.assertTrue(string.is_fullword)

    def test_rule_with_hex_string(self):
        yara_file = yaramod.parse_string('''
rule rule_with_hex_string {
    strings:
        $1 = { 01 23 45 67 89 AB CD EF }
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'rule_with_hex_string')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(len(rule.strings), 1)

        string = rule.strings[0]
        self.assertTrue(string.is_hex)
        self.assertEqual(string.identifier, '$1')
        self.assertEqual(string.text, '{ 01 23 45 67 89 AB CD EF }')

    def test_rule_with_regexp(self):
        yara_file = yaramod.parse_string('''
rule rule_with_regexp {
    strings:
        $1 = /abcd/
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'rule_with_regexp')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Empty)
        self.assertEqual(len(rule.strings), 1)

        string = rule.strings[0]
        self.assertTrue(string.is_regexp)
        self.assertEqual(string.identifier, '$1')
        self.assertEqual(string.text, '/abcd/')

    def test_global_rule(self):
        yara_file = yaramod.parse_string('''
global rule global_rule {
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'global_rule')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Global)
        self.assertTrue(rule.is_global)
        self.assertFalse(rule.is_private)

    def test_private_rule(self):
        yara_file = yaramod.parse_string('''
private rule private_rule {
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertEqual(rule.name, 'private_rule')
        self.assertEqual(rule.modifier, yaramod.RuleModifier.Private)
        self.assertFalse(rule.is_global)
        self.assertTrue(rule.is_private)

    def test_import(self):
        yara_file = yaramod.parse_string('''
import "pe"

rule dummy_rule {
    condition:
        true
}''')

        self.assertEqual(len(yara_file.imports), 1)
        self.assertEqual(len(yara_file.rules), 1)

        module = yara_file.imports[0]
        self.assertEqual(module.name, 'pe')

    def test_bool_literal_condition(self):
        yara_file = yaramod.parse_string('''
rule bool_literal_condition {
    condition:
        false
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.BoolLiteralExpression))
        self.assertEqual(rule.condition.text, 'false')

    def test_int_literal_condition(self):
        yara_file = yaramod.parse_string('''
rule int_literal_condition {
    condition:
        10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, '10')

    def test_double_literal_condition(self):
        yara_file = yaramod.parse_string('''
rule double_literal_condition {
    condition:
        1.23
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.DoubleLiteralExpression))
        self.assertEqual(rule.condition.text, '1.23')

    def test_string_condition(self):
        yara_file = yaramod.parse_string('''
rule string_condition {
    strings:
        $1 = "Hello World!"
    condition:
        $1
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StringExpression))
        self.assertEqual(rule.condition.text, '$1')

    def test_string_at_condition(self):
        yara_file = yaramod.parse_string('''
rule string_at_condition {
    strings:
        $1 = "Hello World!"
    condition:
        $1 at entrypoint
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StringAtExpression))
        self.assertTrue(isinstance(rule.condition.at_expr, yaramod.EntrypointExpression))
        self.assertEqual(rule.condition.text, '$1 at entrypoint')

    def test_string_in_range_condition(self):
        yara_file = yaramod.parse_string('''
rule string_in_condition {
    strings:
        $1 = "Hello World!"
    condition:
        $1 in (10 .. 20)
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StringInRangeExpression))
        self.assertTrue(isinstance(rule.condition.range_expr, yaramod.RangeExpression))
        self.assertEqual(rule.condition.text, '$1 in (10 .. 20)')

    def test_not_condition(self):
        yara_file = yaramod.parse_string('''
rule not_condition {
    condition:
        not true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.NotExpression))
        self.assertTrue(isinstance(rule.condition.operand, yaramod.BoolLiteralExpression))
        self.assertEqual(rule.condition.text, 'not true')

    def test_unary_minus_condition(self):
        yara_file = yaramod.parse_string('''
rule unary_minus_condition {
    condition:
        -10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.UnaryMinusExpression))
        self.assertTrue(isinstance(rule.condition.operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, '-10')

    def test_and_condition(self):
        yara_file = yaramod.parse_string('''
rule and_condition {
    condition:
        true and not false
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.AndExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.BoolLiteralExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.NotExpression))
        self.assertEqual(rule.condition.text, 'true and not false')

    def test_or_condition(self):
        yara_file = yaramod.parse_string('''
rule or_condition {
    condition:
        true or not false
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.OrExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.BoolLiteralExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.NotExpression))
        self.assertEqual(rule.condition.text, 'true or not false')

    def test_less_than_condition(self):
        yara_file = yaramod.parse_string('''
rule less_than_condition {
    condition:
        filesize < 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.LtExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize < 10')

    def test_greater_than_condition(self):
        yara_file = yaramod.parse_string('''
rule greater_than_condition {
    condition:
        filesize > 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.GtExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize > 10')

    def test_less_equal_condition(self):
        yara_file = yaramod.parse_string('''
rule less_equal_condition {
    condition:
        filesize <= 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.LeExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize <= 10')

    def test_greater_than_condition(self):
        yara_file = yaramod.parse_string('''
rule greater_than_condition {
    condition:
        filesize >= 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.GeExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize >= 10')

    def test_equal_condition(self):
        yara_file = yaramod.parse_string('''
rule equal_condition {
    condition:
        filesize == 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.EqExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize == 10')

    def test_not_equal_condition(self):
        yara_file = yaramod.parse_string('''
rule equal_condition {
    condition:
        filesize != 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.NeqExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize != 10')

    def test_parentheses_condition(self):
        yara_file = yaramod.parse_string('''
rule parentheses_condition {
    condition:
        (true)
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.ParenthesesExpression))
        self.assertTrue(isinstance(rule.condition.enclosed_expr, yaramod.BoolLiteralExpression))
        self.assertEqual(rule.condition.text, '(true)')

    def test_plus_condition(self):
        yara_file = yaramod.parse_string('''
rule plus_condition {
    condition:
        filesize + 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.PlusExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize + 10')

    def test_minus_condition(self):
        yara_file = yaramod.parse_string('''
rule minus_condition {
    condition:
        filesize - 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.MinusExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize - 10')

    def test_minus_condition(self):
        yara_file = yaramod.parse_string('''
rule minus_condition {
    condition:
        filesize - 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.MinusExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize - 10')

    def test_multiply_condition(self):
        yara_file = yaramod.parse_string('''
rule multiply_condition {
    condition:
        filesize * 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.MultiplyExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize * 10')

    def test_divide_condition(self):
        yara_file = yaramod.parse_string('''
rule divide_condition {
    condition:
        filesize \ 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.DivideExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize \ 10')

    def test_modulo_condition(self):
        yara_file = yaramod.parse_string('''
rule modulo_condition {
    condition:
        filesize % 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.ModuloExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize % 10')

    def test_shift_left_condition(self):
        yara_file = yaramod.parse_string('''
rule shift_left_condition {
    condition:
        filesize << 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.ShiftLeftExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize << 10')

    def test_shift_right_condition(self):
        yara_file = yaramod.parse_string('''
rule shift_right_condition {
    condition:
        filesize >> 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.ShiftRightExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize >> 10')

    def test_bitwise_not_condition(self):
        yara_file = yaramod.parse_string('''
rule xor_condition {
    condition:
        ~10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.BitwiseNotExpression))
        self.assertTrue(isinstance(rule.condition.operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, '~10')

    def test_xor_condition(self):
        yara_file = yaramod.parse_string('''
rule xor_condition {
    condition:
        filesize ^ 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.BitwiseXorExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize ^ 10')

    def test_bitwise_and_condition(self):
        yara_file = yaramod.parse_string('''
rule bitwise_and_condition {
    condition:
        filesize & 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.BitwiseAndExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize & 10')

    def test_bitwise_or_condition(self):
        yara_file = yaramod.parse_string('''
rule bitwise_or_condition {
    condition:
        filesize | 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.BitwiseOrExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize | 10')

    def test_bitwise_or_condition(self):
        yara_file = yaramod.parse_string('''
rule bitwise_or_condition {
    condition:
        filesize | 10
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.BitwiseOrExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.KeywordExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, 'filesize | 10')

    def test_int_function_condition(self):
        yara_file = yaramod.parse_string('''
rule int_function_condition {
    condition:
        int32be(5)
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.IntFunctionExpression))
        self.assertTrue(isinstance(rule.condition.argument, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.function, 'int32be')
        self.assertEqual(rule.condition.text, 'int32be(5)')

    def test_contains_condition(self):
        yara_file = yaramod.parse_string('''
rule contains_condition {
    condition:
        "Hello" contains "Hell"
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.ContainsExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.StringLiteralExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.StringLiteralExpression))
        self.assertEqual(rule.condition.text, '"Hello" contains "Hell"')

    def test_matches_condition(self):
        yara_file = yaramod.parse_string('''
rule matches_condition {
    condition:
        "Hello" matches /^Hell.*$/
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.MatchesExpression))
        self.assertTrue(isinstance(rule.condition.left_operand, yaramod.StringLiteralExpression))
        self.assertTrue(isinstance(rule.condition.right_operand, yaramod.RegexpExpression))
        self.assertEqual(rule.condition.text, '"Hello" matches /^Hell.*$/')

    def test_match_count_condition(self):
        yara_file = yaramod.parse_string('''
rule match_count_condition {
    strings:
        $1 = "Hello World"
    condition:
        #1
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StringCountExpression))
        self.assertEqual(rule.condition.text, '#1')

    def test_match_offset_condition(self):
        yara_file = yaramod.parse_string('''
rule match_offset_condition {
    strings:
        $1 = "Hello World"
    condition:
        @1
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StringOffsetExpression))
        self.assertEqual(rule.condition.index_expr, None)
        self.assertEqual(rule.condition.text, '@1')

    def test_match_offset_with_index_condition(self):
        yara_file = yaramod.parse_string('''
rule match_offset_with_index_condition {
    strings:
        $1 = "Hello World"
    condition:
        @1[0]
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StringOffsetExpression))
        self.assertTrue(isinstance(rule.condition.index_expr, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, '@1[0]')

    def test_match_length_condition(self):
        yara_file = yaramod.parse_string('''
rule match_length_condition {
    strings:
        $1 = "Hello World"
    condition:
        !1
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StringLengthExpression))
        self.assertEqual(rule.condition.index_expr, None)
        self.assertEqual(rule.condition.text, '!1')

    def test_match_length_with_index_condition(self):
        yara_file = yaramod.parse_string('''
rule match_length_with_index_condition {
    strings:
        $1 = "Hello World"
    condition:
        !1[0]
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StringLengthExpression))
        self.assertTrue(isinstance(rule.condition.index_expr, yaramod.IntLiteralExpression))
        self.assertEqual(rule.condition.text, '!1[0]')

    def test_function_call_condition(self):
        yara_file = yaramod.parse_string('''
import "pe"

rule function_call_condition {
    condition:
        pe.is_dll()
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.FunctionCallExpression))
        self.assertEqual(rule.condition.text, 'pe.is_dll()')

    def test_structure_access_condition(self):
        yara_file = yaramod.parse_string('''
import "pe"

rule structure_access_condition {
    condition:
        pe.linker_version.major
}''')


        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.StructAccessExpression))
        self.assertEqual(rule.condition.text, 'pe.linker_version.major')

    def test_array_access_condition(self):
        yara_file = yaramod.parse_string('''
import "pe"

rule array_access_condition {
    condition:
        pe.sections[0]
}''')


        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.ArrayAccessExpression))
        self.assertEqual(rule.condition.text, 'pe.sections[0]')

    def test_for_integer_set_condition(self):
        yara_file = yaramod.parse_string('''
import "pe"

rule for_integer_set_condition {
    condition:
        for all i in (1,2,3) : ( i )
}''')


        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.ForIntExpression))
        self.assertTrue(isinstance(rule.condition.variable, yaramod.AllExpression))
        self.assertTrue(isinstance(rule.condition.iterated_set, yaramod.SetExpression))
        self.assertTrue(isinstance(rule.condition.body, yaramod.IdExpression))
        self.assertEqual(rule.condition.text, 'for all i in (1, 2, 3) : ( i )')

    def test_for_string_set_condition(self):
        yara_file = yaramod.parse_string('''
import "pe"

rule for_string_set_condition {
    strings:
        $a = "dummy1"
        $b = "dummy2"
    condition:
        for any of ($a,$b) : ( $ at entrypoint )
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.ForStringExpression))
        self.assertTrue(isinstance(rule.condition.variable, yaramod.AnyExpression))
        self.assertTrue(isinstance(rule.condition.iterated_set, yaramod.SetExpression))
        self.assertTrue(isinstance(rule.condition.body, yaramod.StringAtExpression))
        self.assertEqual(rule.condition.text, 'for any of ($a, $b) : ( $ at entrypoint )')

    def test_of_condition(self):
        yara_file = yaramod.parse_string('''
import "pe"

rule of_condition {
    strings:
        $a = "dummy1"
        $b = "dummy2"
    condition:
        1 of ($a,$b)
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        self.assertTrue(isinstance(rule.condition, yaramod.OfExpression))
        self.assertTrue(isinstance(rule.condition.variable, yaramod.IntLiteralExpression))
        self.assertTrue(isinstance(rule.condition.iterated_set, yaramod.SetExpression))
        self.assertEqual(rule.condition.body, None)
        self.assertEqual(rule.condition.text, '1 of ($a, $b)')

    def test_parser_error(self):
        self.assertRaises(yaramod.ParserError, yaramod.parse_string, 'rule {')
