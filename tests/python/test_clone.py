import unittest
import yaramod


class CloneTests(unittest.TestCase):
    def test_condition_clone(self):
        yara_file = yaramod.Yaramod().parse_string('''
rule test
{
	strings:
		$str = "Hello"
	condition:
		$str
}
''')

        new_ts = yaramod.TokenStream()
        cloned = yara_file.rules[0].condition.clone(new_ts)

        self.assertEqual(cloned.text, '$str')
