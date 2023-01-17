import unittest
import yaramod


class TokenStreamTests(unittest.TestCase):

    def test_find_token(self):
        yara_file = yaramod.Yaramod(yaramod.Features.Avast).parse_string('''
rule rule_with_unordered_sections
{
	variables:
		var = 25.8
	strings:
		$1 = "Hello World!"
	condition:
		true
}''')
        ts = yara_file.tokenstream

        itr = ts.find(yaramod.TokenType.ImportKeyword)
        self.assertEqual(itr, ts.end)

        itr = ts.find(yaramod.TokenType.StringLiteral)
        self.assertNotEqual(itr, ts.end)
        self.assertEqual(itr.value.text, '"Hello World!"')

        self.assertEqual(itr.previous().value.type, yaramod.TokenType.Assign)
        self.assertEqual(itr.next().value.type, yaramod.TokenType.NewLine)

        range_itr = ts.find_range(yaramod.TokenType.Variables, itr, ts.end)
        self.assertEqual(range_itr, ts.end)

        range_itr = ts.find_range(yaramod.TokenType.Variables, ts.begin, itr)
        self.assertNotEqual(range_itr, ts.end)

    def test_iteration(self):
        EXPECTED_TOKEN_TYPES = [
            yaramod.TokenType.NewLine,
            yaramod.TokenType.Rule,
            yaramod.TokenType.RuleName,
            yaramod.TokenType.NewLine,
            yaramod.TokenType.RuleBegin,
            yaramod.TokenType.NewLine,
            yaramod.TokenType.Variables,
            yaramod.TokenType.ColonBeforeNewline,
            yaramod.TokenType.NewLine,
            yaramod.TokenType.VariableKey,
            yaramod.TokenType.Assign,
            yaramod.TokenType.Double,
            yaramod.TokenType.NewLine,
            yaramod.TokenType.Condition,
            yaramod.TokenType.ColonBeforeNewline,
            yaramod.TokenType.NewLine,
            yaramod.TokenType.BoolTrue,
            yaramod.TokenType.NewLine,
            yaramod.TokenType.RuleEnd,
        ]

        yara_file = yaramod.Yaramod(yaramod.Features.Avast).parse_string('''
rule rule_with_unordered_sections
{
	variables:
		var = 25.8
	condition:
		true
}''')
        ts = yara_file.tokenstream

        itr = ts.begin
        idx = 0
        while itr != ts.end:
            self.assertEqual(itr.value.type, EXPECTED_TOKEN_TYPES[idx], f"Bad token type at index {idx}")
            itr.increment()
            idx += 1

        self.assertEqual(len(EXPECTED_TOKEN_TYPES), idx, f"Unexpected length of token stream")

        itr = ts.end
        idx = len(EXPECTED_TOKEN_TYPES)
        while True:
            itr.decrement()
            idx -= 1
            self.assertEqual(itr.value.type, EXPECTED_TOKEN_TYPES[idx], f"Bad token type at index {idx}")

            if itr == ts.begin:
                break

        self.assertEqual(0, idx, f"Unexpected length of token stream")


    def test_modify_stream(self):
        yara_file = yaramod.Yaramod().parse_string('''
rule rule_with_metas {
    meta:
        str_meta = "string meta"
        int_meta = 42
        bool_meta = true
    condition:
        true
}''')
        RULE_EXPECTED = """
rule rule_with_metas
{
\tmeta:
\t\tstr_meta = "string meta"

\t\tbool_meta = true
\t\tbetter_meta = 42
\tcondition:
\t\ttrue
}
"""


        ts = yara_file.tokenstream

        itr = ts.begin
        while itr != ts.end:
            itr = ts.find_range(yaramod.TokenType.MetaKey, itr, ts.end)
            if itr == ts.end:
                break

            if itr.value.string == "int_meta":
                end = ts.find_range(yaramod.TokenType.MetaValue, itr, ts.end)
                itr = ts.erase_range(itr, end.next())
            else:
                itr.increment()

        itr = ts.find(yaramod.TokenType.Condition)
        ts.insert(itr, yaramod.TokenType.MetaKey, yaramod.Literal("better_meta"))
        ts.insert(itr, yaramod.TokenType.Assign, yaramod.Literal("="))
        ts.insert(itr, yaramod.TokenType.MetaValue, yaramod.Literal(42))
        ts.insert(itr, yaramod.TokenType.NewLine, yaramod.Literal("\n"))

        self.assertEqual(yara_file.text_formatted, RULE_EXPECTED)
