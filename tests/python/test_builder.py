import unittest
import yaramod


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.new_file = yaramod.YaraFileBuilder()
        self.new_rule = yaramod.YaraRuleBuilder()

    def test_empty_file(self):
        yara_file = self.new_file.get()

        self.assertEqual(yara_file.text, '')

    def test_pure_imports(self):
        yara_file = self.new_file \
            .with_module('pe') \
            .with_module('elf') \
            .get()

        self.assertEqual(yara_file.text, '''import "pe"
import "elf"
''')

    def test_empty_rule(self):
        rule = self.new_rule \
            .with_name('empty_rule') \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()

        self.assertEqual(yara_file.text, '''rule empty_rule {
	condition:
		true
}''')

    def test_rule_with_metas(self):
        rule = self.new_rule \
            .with_name('rule_with_metas') \
            .with_string_meta('string_meta', 'string value') \
            .with_int_meta('int_meta', 42) \
            .with_hex_int_meta('hex_int_meta', 0x42) \
            .with_bool_meta('bool_meta', False) \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()

        self.assertEqual(yara_file.text, '''rule rule_with_metas {
	meta:
		string_meta = "string value"
		int_meta = 42
		hex_int_meta = 0x42
		bool_meta = false
	condition:
		true
}''')

    def test_rule_with_tags(self):
        rule = self.new_rule \
            .with_name('rule_with_tags') \
            .with_tag('Tag1') \
            .with_tag('Tag2') \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()

        self.assertEqual(yara_file.text, '''rule rule_with_tags : Tag1 Tag2 {
	condition:
		true
}''')

    def test_rule_with_modifiers(self):
        rule = self.new_rule \
            .with_name('private_rule') \
            .with_modifier(yaramod.RuleModifier.Private) \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()

        self.assertEqual(yara_file.text, '''private rule private_rule {
	condition:
		true
}''')

    def test_rule_with_plain_string(self):
        rule = self.new_rule \
            .with_name('rule_with_plain_string') \
            .with_plain_string('$1', 'This is plaing string.', yaramod.StringModifiers.Ascii | yaramod.StringModifiers.Wide) \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()

        self.assertEqual(yara_file.text, '''rule rule_with_plain_string {
	strings:
		$1 = "This is plaing string." ascii wide
	condition:
		true
}''')

    def test_rule_with_hex_string(self):
        rule = self.new_rule \
            .with_name('rule_with_hex_string') \
            .with_hex_string('$1', yaramod.YaraHexStringBuilder([0x10, 0x11]).get()) \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()

        self.assertEqual(yara_file.text, '''rule rule_with_hex_string {
	strings:
		$1 = { 10 11 }
	condition:
		true
}''')

    def test_rule_with_regexp(self):
        rule = self.new_rule \
            .with_name('rule_with_regexp') \
            .with_regexp('$1', '[a-z0-9]{32}', 'i') \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()

        self.assertEqual(yara_file.text, '''rule rule_with_regexp {
	strings:
		$1 = /[a-z0-9]{32}/i
	condition:
		true
}''')

    def test_multiple_rules(self):
        rule1 = self.new_rule \
            .with_name('rule_1') \
            .with_tag('Tag1') \
            .with_plain_string('$1', 'This is plaing string 1.') \
            .get()
        rule2 = self.new_rule \
            .with_name('rule_2') \
            .with_tag('Tag2') \
            .with_plain_string('$2', 'This is plaing string 2.') \
            .get()
        yara_file = self.new_file \
            .with_rule(rule1) \
            .with_rule(rule2) \
            .get()

        self.assertEqual(yara_file.text, '''rule rule_1 : Tag1 {
	strings:
		$1 = "This is plaing string 1."
	condition:
		true
}

rule rule_2 : Tag2 {
	strings:
		$2 = "This is plaing string 2."
	condition:
		true
}''')

    def test_rule_with_condition(self):
        cond = yaramod.filesize() >= yaramod.int_val(100)
        rule = self.new_rule \
            .with_name('rule_with_condition') \
            .with_condition(cond.get()) \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()


        self.assertEqual(yara_file.text, '''rule rule_with_condition {
	condition:
		filesize >= 100
}''')

    def test_rule_with_complex_condition(self):
        cond = yaramod.for_loop(
                yaramod.any(),
                'i',
                yaramod.set([
                    yaramod.int_val(1),
                    yaramod.int_val(2),
                    yaramod.int_val(3)
                ]),
                yaramod.match_at(
                    '$1',
                    yaramod.paren(
                        yaramod.entrypoint() + yaramod.id('i')
                    )
                )
            )
        rule = self.new_rule \
            .with_name('rule_with_complex_condition') \
            .with_plain_string('$1', 'This is plaing string.') \
            .with_condition(cond.get()) \
            .get()
        yara_file = self.new_file \
            .with_rule(rule) \
            .get()


        self.assertEqual(yara_file.text, '''rule rule_with_complex_condition {
	strings:
		$1 = "This is plaing string."
	condition:
		for any i in (1, 2, 3) : ( $1 at (entrypoint + i) )
}''')
