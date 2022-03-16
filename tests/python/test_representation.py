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

    def test_module_interface(self):
        modules = yaramod.Yaramod().modules

        # module cuckoo
        self.assertTrue("cuckoo" in modules)
        cuckoo_symbol = modules["cuckoo"].structure
        self.assertEqual("cuckoo", cuckoo_symbol.name)
        self.assertTrue(cuckoo_symbol.is_structure)
        cuckoo_attributes = cuckoo_symbol.attributes

        self.assertTrue("network" in cuckoo_attributes)
        network_symbol = cuckoo_attributes["network"]
        self.assertTrue(network_symbol.is_structure)
        network_attributes = network_symbol.attributes

        self.assertTrue("http_get" in network_attributes)
        http_get_symbol = network_attributes["http_get"]
        self.assertTrue(http_get_symbol.is_function)
        self.assertEqual("http_get", http_get_symbol.name)
        self.assertEqual(http_get_symbol.return_type, yaramod.ExpressionType.Int)
        http_get_overloads = http_get_symbol.overloads
        self.assertEqual(len(http_get_overloads), 1)
        self.assertEqual(http_get_overloads[0], [yaramod.ExpressionType.Regexp])

        # module pe
        self.assertTrue("pe" in modules)
        pe_symbol = modules["pe"].structure
        self.assertEqual("pe", pe_symbol.name)
        self.assertTrue(pe_symbol.is_structure)
        pe_attributes = pe_symbol.attributes

        self.assertTrue("MACHINE_UNKNOWN" in pe_attributes)
        machine_symbol = pe_attributes["MACHINE_UNKNOWN"]
        self.assertTrue(machine_symbol.is_value)
        self.assertEqual(machine_symbol.data_type, yaramod.ExpressionType.Int)

        self.assertTrue("version_info" in pe_attributes)
        version_info_symbol = pe_attributes["version_info"]
        self.assertEqual(version_info_symbol.documentation[0:10], "Dictionary")

        self.assertTrue("sections" in pe_attributes)
        section_array_symbol = pe_attributes['sections']
        self.assertEqual(section_array_symbol.name, 'sections')
        self.assertTrue(section_array_symbol.is_array)
        self.assertEqual(section_array_symbol.element_type, yaramod.ExpressionType.Object)
        self.assertEqual(section_array_symbol.documentation[0:10], 'Individual')
        section_symbol = section_array_symbol.structure
        self.assertEqual(section_symbol.name, 'sections')
        self.assertTrue(section_symbol.is_structure)
        section_attributes = section_symbol.attributes

        self.assertTrue("characteristics" in section_attributes)

    def test_custom_module_interface(self):
        modules = yaramod.Yaramod(yaramod.Features.AllCurrent, "./tests/python/testing_modules").modules

        # module module_test
        self.assertTrue("module_test" in modules)
        module_symbol = modules["module_test"].structure
        self.assertEqual("module_test", module_symbol.name)
        self.assertTrue(module_symbol.is_structure)
        cuckoo_attributes = module_symbol.attributes

        self.assertTrue("structure_test" in cuckoo_attributes)
        structure_symbol = cuckoo_attributes["structure_test"]
        self.assertTrue(structure_symbol.is_structure)
        structure_attributes = structure_symbol.attributes

        self.assertTrue("function_test" in structure_attributes)
        function_symbol = structure_attributes["function_test"]
        self.assertTrue(function_symbol.is_function)
        self.assertEqual(function_symbol.return_type, yaramod.ExpressionType.String)
        function_overloads = function_symbol.overloads
        self.assertEqual(len(function_overloads), 2)
        self.assertEqual(function_overloads[0], [yaramod.ExpressionType.Regexp])
        self.assertEqual(function_overloads[1], [yaramod.ExpressionType.Regexp, yaramod.ExpressionType.String])
        function_documentations = function_symbol.documentations
        print(function_documentations)
        self.assertEqual(len(function_documentations), 2)
        self.assertEqual(function_documentations[0], "Testing function overload documentation.")
        self.assertEqual(function_documentations[1], "Testing function cool overload documentation.")

        self.assertTrue("value_test" in cuckoo_attributes)
        value_symbol = cuckoo_attributes["value_test"]
        self.assertTrue(value_symbol.is_value)
        self.assertEqual(value_symbol.documentation, "Testing value documentation. Example: ```module_test.value_test > 10```")

        self.assertTrue("reference_test" in cuckoo_attributes)
        reference_symbol = cuckoo_attributes["reference_test"]
        self.assertTrue(reference_symbol.is_reference)
        self.assertEqual(reference_symbol.symbol, structure_symbol)

        self.assertTrue("references_test" in cuckoo_attributes)
        references_symbol = cuckoo_attributes["references_test"]
        self.assertTrue(references_symbol.is_array)
        self.assertTrue(references_symbol.structure.is_reference)
        self.assertEqual(references_symbol.structure.symbol, structure_symbol)

    def test_custom_module_enhancing_known_module(self):
        modules = yaramod.Yaramod(yaramod.Features.AllCurrent, "./tests/python/testing_modules").modules

        # module cuckoo
        self.assertTrue("cuckoo" in modules)
        cuckoo_symbol = modules["cuckoo"].structure
        self.assertEqual("cuckoo", cuckoo_symbol.name)
        self.assertTrue(cuckoo_symbol.is_structure)
        cuckoo_attributes = cuckoo_symbol.attributes

        # module pe - added of an overload
        self.assertTrue("pe" in modules)
        pe_symbol = modules["pe"].structure
        self.assertEqual("pe", pe_symbol.name)
        pe_attributes = pe_symbol.attributes

        # other pe json does not delete functions from base pe json:
        self.assertTrue("MACHINE_AM33" in pe_attributes)
        machine_symbol = pe_attributes["MACHINE_AM33"]
        self.assertTrue(machine_symbol.is_value)
        self.assertEqual(machine_symbol.data_type, yaramod.ExpressionType.Int)

        # no problem with multiple definitions of the same symbol if those definitions are compatible:
        self.assertTrue("MACHINE_TEST_VALUE" in pe_attributes)
        machine_symbol = pe_attributes["MACHINE_TEST_VALUE"]
        self.assertTrue(machine_symbol.is_value)
        self.assertEqual(machine_symbol.data_type, yaramod.ExpressionType.Int)

        self.assertTrue("sections" in pe_attributes)
        section_array_symbol = pe_attributes['sections']
        self.assertEqual(section_array_symbol.name, 'sections')
        self.assertTrue(section_array_symbol.is_array)
        self.assertEqual(section_array_symbol.element_type, yaramod.ExpressionType.Object)
        self.assertEqual(section_array_symbol.documentation[0:10], 'Individual')
        section_symbol = section_array_symbol.structure
        self.assertEqual(section_symbol.name, 'sections')
        self.assertTrue(section_symbol.is_structure)
        section_attributes = section_symbol.attributes

        # pe.sections.characteristics still exists:
        self.assertTrue("virtual_address" in section_attributes)
        # pe.sections.test_sections_value is added:
        self.assertTrue("test_sections_value" in section_attributes)
        test_section_value_symbol = section_attributes['test_sections_value']
        self.assertEqual(test_section_value_symbol.name, 'test_sections_value')
        self.assertTrue(test_section_value_symbol.is_value)
        self.assertTrue(test_section_value_symbol.data_type, yaramod.ExpressionType.String)

        self.assertTrue("rich_signature" in pe_attributes)
        rich_signature_symbol = pe_attributes['rich_signature']
        self.assertTrue(rich_signature_symbol.is_structure)
        rich_signature_attributes = rich_signature_symbol.attributes

        self.assertTrue("test_value" in rich_signature_attributes)
        self.assertTrue("version" in rich_signature_attributes)
        version_symbol = rich_signature_attributes['version']
        self.assertTrue(version_symbol.is_function)
        version_overloads = version_symbol.overloads
        self.assertEqual(len(version_overloads), 3)
        self.assertEqual(version_overloads[0], [yaramod.ExpressionType.Int])
        self.assertEqual(version_overloads[1], [yaramod.ExpressionType.Int, yaramod.ExpressionType.Int])
        self.assertEqual(version_overloads[2], [yaramod.ExpressionType.Int, yaramod.ExpressionType.String])
        version_overloads_names = version_symbol.argument_names
        self.assertEqual(version_overloads_names[0], ["version"])
        self.assertEqual(version_overloads_names[1], ["version", "toolid"])
        self.assertEqual(version_overloads_names[2], ["version", "test string argument"])
