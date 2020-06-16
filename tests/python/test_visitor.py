import unittest
import yaramod


class VisitorTests(unittest.TestCase):
    def test_modifying_visitor_inpact_on_regexp_expression(self):
        class RegexpCaseInsesitiveAdder(yaramod.ModifyingVisitor):
            def add(self, yara_file: yaramod.YaraFile):
                for rule in yara_file.rules:
                    self.modify(rule.condition)

            def visit_RegexpExpression(self, expr: yaramod.Expression):
                output = yaramod.regexp('abc', 'i').get()
                expr.exchange_tokens(output)
                return output

        yara_file = yaramod.Yaramod().parse_string(r'''
import "cuckoo"
rule rule_with_regexp_in_fnc_call {
	condition:
		cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/)
}''')

        regexp_icase_adder = RegexpCaseInsesitiveAdder()
        regexp_icase_adder.add(yara_file)

        self.assertEqual(len(yara_file.rules), 1)
        rule = yara_file.rules[0]
        cond = rule.condition
        self.assertTrue(isinstance(cond, yaramod.FunctionCallExpression))
        self.assertEqual(len(cond.arguments), 1)
        self.assertTrue(isinstance(cond.arguments[0], yaramod.RegexpExpression))
        self.assertTrue(isinstance(cond.arguments[0].regexp_string, yaramod.Regexp))
        self.assertEqual(cond.arguments[0].regexp_string.text, r'/abc/i')
        self.assertEqual(cond.arguments[0].regexp_string.pure_text, rb'abc')

        self.assertEqual(r'''import "cuckoo"

rule rule_with_regexp_in_fnc_call {
	condition:
		cuckoo.network.http_request(/abc/i)
}''', yara_file.text)
        expected = r'''
import "cuckoo"

rule rule_with_regexp_in_fnc_call
{
	condition:
		cuckoo.network.http_request(/abc/i)
}
'''
        self.assertEqual(expected, yara_file.text_formatted)

    def test_modifying_visitor_eq_expression(self):
        class EqModifyer(yaramod.ModifyingVisitor):
            def add(self, yara_file: yaramod.YaraFile):
                for rule in yara_file.rules:
                    rule.condition = self.modify(rule.condition)

            def visit_EqExpression(self, expr: yaramod.Expression):
                context = yaramod.TokenStreamContext(expr)
                expr.left_operand.accept(self)
                expr.right_operand.accept(self)
                output = (yaramod.YaraExpressionBuilder(expr.right_operand) != yaramod.YaraExpressionBuilder(expr.left_operand)).get()

                self.cleanUpTokenStreams(context, output)
                return output

        yara_file = yaramod.Yaramod().parse_string(r'''
rule rule_with_regexp_in_fnc_call {
	strings:
		$str1 = "a"
		$str2222 = "b"
	condition:
		!str1 == !str2222
}''')

        regexp_icase_adder = EqModifyer()
        regexp_icase_adder.add(yara_file)

        self.assertEqual(len(yara_file.rules), 1)
        rule = yara_file.rules[0]
        cond = rule.condition
        self.assertTrue(isinstance(cond, yaramod.NeqExpression))
        self.assertTrue(isinstance(cond.left_operand, yaramod.StringLengthExpression))
        self.assertTrue(isinstance(cond.right_operand, yaramod.StringLengthExpression))

        self.assertEqual(r'''rule rule_with_regexp_in_fnc_call {
	strings:
		$str1 = "a"
		$str2222 = "b"
	condition:
		!str2222 != !str1
}''', yara_file.text)
        expected = r'''
rule rule_with_regexp_in_fnc_call
{
	strings:
		$str1 = "a"
		$str2222 = "b"
	condition:
		!str2222 != !str1
}
'''
        self.assertEqual(expected, yara_file.text_formatted)
