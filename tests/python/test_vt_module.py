import unittest
import yaramod

class VTModuleTests(unittest.TestCase):
    def test_vt_rule(self):
        parsed_file = yaramod.Yaramod().parse_file('./tests/python/testing_rules/test_vt.yar')
        self.assertEqual('''import "vt"

rule new_file_rules {
	condition:
		vt.metadata.new_file
}''', parsed_file.text)