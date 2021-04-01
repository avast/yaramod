import unittest
import yaramod


class RepresentationTests(unittest.TestCase):
    def test_literals(self):
        int_lit = yaramod.Literal(42)
        self.assertTrue(int_lit.is_int)
        self.assertEqual(int_lit.int, 42)
        self.assertEqual(int_lit.uint, 42)
        self.assertEqual(int_lit.text, '42')

        hex_int_lit = yaramod.Literal(42, '0x2A')
        self.assertTrue(hex_int_lit.is_int)
        self.assertEqual(hex_int_lit.int, 42)
        self.assertEqual(hex_int_lit.uint, 42)
        self.assertEqual(hex_int_lit.text, '0x2A')

        str_lit = yaramod.Literal('hello')
        self.assertTrue(str_lit.is_string)
        self.assertEqual(str_lit.string, 'hello')
        self.assertEqual(str_lit.text, '"hello"')

        bool_lit = yaramod.Literal(True)
        self.assertTrue(bool_lit.is_bool)
        self.assertEqual(bool_lit.bool, True)
        self.assertEqual(bool_lit.text, 'true')

    def test_change_meta_of_rule(self):
        yara_file = yaramod.Yaramod().parse_string('''
rule empty_rule {
	meta:
		key = "value"
	condition:
		true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        rule.metas[0].value = yaramod.Literal('another value')

        expected = '''
rule empty_rule
{
	meta:
		key = "another value"
	condition:
		true
}
'''
        self.assertEqual(expected, yara_file.text_formatted)

    def test_get_tokenstream(self):
        yara_file = yaramod.Yaramod().parse_string('''
rule empty_rule {
    meta:
        key = "value"
    condition:
        true
}''')

        self.assertEqual(len(yara_file.rules), 1)

        rule = yara_file.rules[0]
        rule.metas[0].value = yaramod.Literal('another value')

        ts = yara_file.tokenstream
        self.assertFalse(ts.empty)
        self.assertEqual(ts.front.pure_text, '\n')
        self.assertEqual(ts.back.pure_text, '}')
        self.assertEqual(ts.tokens_as_text, [ '\n',
            'rule', 'empty_rule', '{', '\n',
            'meta', ':', '\n',
            'key', '=', 'another value', '\n',
            'condition', ':', '\n', 'true', '\n',
            '}'
        ])
        condition_ts = rule.condition.tokenstream
        self.assertEqual(condition_ts.tokens_as_text, [ '\n',
            'rule', 'empty_rule', '{', '\n',
            'meta', ':', '\n',
            'key', '=', 'another value', '\n',
            'condition', ':', '\n', 'true', '\n',
            '}'
        ])

    def test_get_tokenstream_after_syntax_error_1(self):
        input_text = '''
rule dummy_rule {
	condition
		true
}'''
        ymod = yaramod.Yaramod()
        try:
            ymod.parse_string(input_text)
        except:
            ts = ymod.yara_file.tokenstream
            self.assertFalse(ts.empty)
            self.assertEqual(ts.front.pure_text, '\n')
            self.assertEqual(ts.back.pure_text, 'true')

    def test_get_tokenstream_after_syntax_error_2(self):
        input_text = '''
rule dummy_rule {
	condition:
		true ) and false
}'''
        ymod = yaramod.Yaramod()
        try:
            ymod.parse_string(input_text)
        except:
            ts = ymod.yara_file.tokenstream
            self.assertFalse(ts.empty)
            self.assertEqual(ts.front.pure_text, '\n')
            self.assertEqual(ts.back.pure_text, ')')

    def test_get_tokenstream_after_unknown_identifier_error(self):
        input_text = '''
rule dummy_rule {
	condition:
		blah or true
}'''
        ymod = yaramod.Yaramod()
        try:
            ymod.parse_string(input_text)
        except:
            ts = ymod.yara_file.tokenstream
            self.assertFalse(ts.empty)
            self.assertEqual(ts.front.pure_text, '\n')
            # After 'blah', also 'or' got into TS, because 'blah' is not tested by the grammar, it is semantics issue
            self.assertEqual(ts.back.pure_text, 'or')

    def test_get_tokenstream_after_unknown_module_error(self):
        input_text = '''
import "unknown"

rule dummy_rule {
	condition:
		true
}'''
        ymod = yaramod.Yaramod()
        try:
            ymod.parse_string(input_text)
        except:
            ts = ymod.yara_file.tokenstream
            self.assertFalse(ts.empty)
            # After 'unknown', also 'rule' got into TS, because 'unknown' is not tested by the grammar, it is semantics issue
            self.assertEqual(ts.tokens_as_text, [ '\n',
                'import', 'unknown', '\n',
                '\n',
                'rule'
            ])

    def test_meta_values_interface(self):
        input_text = """rule test {
    meta:
        author = "Name Surname"
        description = "Test checking the meta value tokens"
    condition:
        false
}
"""
        ymod = yaramod.Yaramod()
        yfile = ymod.parse_string(input_text)
        self.assertEqual(len(yfile.rules[0].metas), 2)

        meta = yfile.rules[0].metas[0]  # author
        self.assertTrue(hasattr(meta, "token_key"))
        token = meta.token_key
        self.assertEqual(token.location.begin.line, 3)
        self.assertEqual(token.location.begin.column, 9)
        self.assertEqual(token.location.end.line, 3)
        self.assertEqual(token.location.end.column, 14)

        self.assertTrue(hasattr(meta, "token_value"))
        token = meta.token_value
        self.assertEqual(token.location.begin.line, 3)
        self.assertEqual(token.location.begin.column, 18)
        self.assertEqual(token.location.end.line, 3)
        self.assertEqual(token.location.end.column, 31)

        meta = yfile.rules[0].metas[1]  # description
        self.assertTrue(hasattr(meta, "token_key"))
        token = meta.token_key
        self.assertEqual(token.location.begin.line, 4)
        self.assertEqual(token.location.begin.column, 9)
        self.assertEqual(token.location.end.line, 4)
        self.assertEqual(token.location.end.column, 19)

        self.assertTrue(hasattr(meta, "token_value"))
        token = meta.token_value
        self.assertEqual(token.location.begin.line, 4)
        self.assertEqual(token.location.begin.column, 23)
        self.assertEqual(token.location.end.line, 4)
        self.assertEqual(token.location.end.column, 59)

def test_get_modulepool(self):
        ymod = yaramod.Yaramod()
        modules = ymod.modules
        self.assertTrue("cuckoo" in modules)
        self.assertTrue("dex" in modules)
        self.assertTrue("elf" in modules)
        self.assertTrue("hash" in modules)
        self.assertTrue("macho" in modules)
        self.assertTrue("magic" in modules)
        self.assertTrue("math" in modules)
        self.assertTrue("pe" in modules)
        self.assertTrue("time" in modules)
