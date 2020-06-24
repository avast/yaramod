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
