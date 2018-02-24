/**
* @file tests/builder_tests.cpp
* @brief Tests for the YARA builder.
* @copyright AVG Technologies s.r.o, All Rights Reserved
*/

#include <gtest/gtest.h>

#include "yaramod/builder/yara_expression_builder.h"
#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/builder/yara_hex_string_builder.h"
#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/types/expressions.h"

using namespace ::testing;

namespace yaramod {
namespace tests {

class BuilderTests : public Test {};

TEST_F(BuilderTests,
EmptyFileWorks) {
	YaraFileBuilder newFile;
	auto yaraFile = newFile.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ("", yaraFile->getText());
}

TEST_F(BuilderTests,
PureImportsWorks) {
	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withModule("pe")
		.withModule("elf")
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(import "pe"
import "elf"
)", yaraFile->getText());
}

TEST_F(BuilderTests,
UnnamedRuleWorks) {
	YaraRuleBuilder newRule;
	auto rule = newRule.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule unknown {
	condition:
		true
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithCustomNameWorks) {
	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_custom_name")
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_custom_name {
	condition:
		true
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithMetasWorks) {
	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_metas")
		.withStringMeta("string_meta", "string value")
		.withIntMeta("int_meta", 42)
		.withHexIntMeta("hex_int_meta", 0x42)
		.withBoolMeta("bool_meta", false)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_metas {
	meta:
		string_meta = "string value"
		int_meta = 42
		hex_int_meta = 0x42
		bool_meta = false
	condition:
		true
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithTagsWorks) {
	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_tags")
		.withTag("Tag1")
		.withTag("Tag2")
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_tags : Tag1 Tag2 {
	condition:
		true
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithModifierWorks) {
	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_modifier")
		.withModifier(Rule::Modifier::Global)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(global rule rule_with_modifier {
	condition:
		true
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithPlainStringWorks) {
	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_plain_string")
		.withPlainString("$1", "This is plain string.", String::Modifiers::Ascii | String::Modifiers::Wide)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_plain_string {
	strings:
		$1 = "This is plain string." ascii wide
	condition:
		true
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithPlainStringPureWideWorks) {
	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_plain_string")
		.withPlainString("$1", "This is plain string.", String::Modifiers::Wide)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_plain_string {
	strings:
		$1 = "This is plain string." wide
	condition:
		true
})", yaraFile->getText());
}

TEST_F(BuilderTests,
MultipleRulesWorks) {
	YaraRuleBuilder newRule;
	auto rule1 = newRule
		.withName("rule_1")
		.withTag("Tag1")
		.withUIntMeta("id", 1)
		.withPlainString("$1", "This is plain string 1.")
		.get();
	auto rule2 = newRule
		.withName("rule_2")
		.withTag("Tag2")
		.withUIntMeta("id", 2)
		.withPlainString("$2", "This is plain string 2.")
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule1))
		.withRule(std::move(rule2))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_1 : Tag1 {
	meta:
		id = 1
	strings:
		$1 = "This is plain string 1."
	condition:
		true
}

rule rule_2 : Tag2 {
	meta:
		id = 2
	strings:
		$2 = "This is plain string 2."
	condition:
		true
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithCustomConditionWorks) {
	auto cond = matchAt("$1", entrypoint()).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_custom_condition")
		.withPlainString("$1", "Hello World!")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_custom_condition {
	strings:
		$1 = "Hello World!"
	condition:
		$1 at entrypoint
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithConditionWithSymbolsWorks) {
	auto cond = forLoop(any(), "i", set({intVal(1), intVal(2), intVal(3)}), matchAt("$1", paren(entrypoint() + id("i")))).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_condition_with_symbols")
		.withPlainString("$1", "Hello World!")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_condition_with_symbols {
	strings:
		$1 = "Hello World!"
	condition:
		for any i in (1, 2, 3) : ( $1 at (entrypoint + i) )
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithHexStringWorks) {
	auto cond = stringRef("$1").get();

	auto alt1 = YaraHexStringBuilder().add(0xBB, 0xCC);
	auto alt2 = YaraHexStringBuilder().add(0xDD, 0xEE);
	auto alt3 = YaraHexStringBuilder().add(0xFF);
	auto alt4 = YaraHexStringBuilder(std::vector<std::uint8_t>{ 0xFE, 0xED });

	YaraHexStringBuilder newHexStr;
	auto hexStr = newHexStr
		.add(0x11, 0x22, wildcard(), wildcardHigh(0xA), wildcardLow(0xB))
		.add(jumpVarying(), jumpFixed(5), jumpVaryingRange(3), jumpRange(3, 5))
		.add(alt(alt(alt1, alt2), alt3, alt4))
		.add(0x99)
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_hex_string")
		.withHexString("$1", hexStr)
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_hex_string {
	strings:
		$1 = { 11 22 ?? ?A B? [-] [5] [3-] [3-5] ( ( BB CC | DD EE ) | FF | FE ED ) 99 }
	condition:
		$1
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithStringForConditionWorks) {
	auto cond = forLoop(any(), set({stringRef("$1"), stringRef("$2")}), matchAt("$", entrypoint())).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_string_for_condition")
		.withPlainString("$1", "Hello World!")
		.withPlainString("$2", "Ahoj Svet!")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_string_for_condition {
	strings:
		$1 = "Hello World!"
		$2 = "Ahoj Svet!"
	condition:
		for any of ($1, $2) : ( $ at entrypoint )
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithOfWorks) {
	auto cond = of(all(), them()).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_of")
		.withPlainString("$1", "Hello World!")
		.withPlainString("$2", "Ahoj Svet!")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_of {
	strings:
		$1 = "Hello World!"
		$2 = "Ahoj Svet!"
	condition:
		all of them
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithRangeWorks) {
	auto cond = matchInRange("$1", range(intVal(0), filesize())).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_range")
		.withPlainString("$1", "Hello World!")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_range {
	strings:
		$1 = "Hello World!"
	condition:
		$1 in (0 .. filesize)
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithStructureWorks) {
	auto cond = (id("pe").access("number_of_sections") > intVal(1)).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_range")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withModule("pe")
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(import "pe"

rule rule_with_range {
	condition:
		pe.number_of_sections > 1
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithArrayAndStructureWorks) {
	auto cond = id("pe").access("sections")[intVal(0)].access("name").contains(stringVal("text"))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_array_and_structure")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withModule("pe")
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(import "pe"

rule rule_with_array_and_structure {
	condition:
		pe.sections[0].name contains "text"
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithFunctionCallWorks) {
	auto cond = id("pe").access("exports")(stringVal("ExitProcess"))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_function_call")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withModule("pe")
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(import "pe"

rule rule_with_function_call {
	condition:
		pe.exports("ExitProcess")
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithIntFunctionWorks) {
	auto cond = (intVal(0).readUInt16(IntFunctionEndianness::Little) == hexIntVal(0x5A4D))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_int_function")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_int_function {
	condition:
		uint16(0) == 0x5a4d
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithArithmeticOperationsWorks) {
	auto cond = (paren(entrypoint() + intVal(100) * intVal(3)) < paren(filesize() - intVal(100) / intVal(2)))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_arithmetic_operations")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_arithmetic_operations {
	condition:
		(entrypoint + 100 * 3) < (filesize - 100 \ 2)
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithBitwiseOperationsWorks) {
	auto cond = (id("pe").access("characteristics") & paren(id("pe").access("DLL") | id("pe").access("RELOCS_STRIPPED")))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_bitwise_operations")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withModule("pe")
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(import "pe"

rule rule_with_bitwise_operations {
	condition:
		pe.characteristics & (pe.DLL | pe.RELOCS_STRIPPED)
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithLogicOperationsWorks) {
	auto cond = (id("pe").access("is_32bit")() && paren((id("pe").access("is_dll")() || paren(id("pe").access("number_of_sections") > intVal(3)))))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_logic_operations")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withModule("pe")
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(import "pe"

rule rule_with_logic_operations {
	condition:
		pe.is_32bit() and (pe.is_dll() or (pe.number_of_sections > 3))
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithIntMultpliersWorks) {
	auto cond = (intVal(100, IntMultiplier::Kilobytes) <= filesize() && filesize() <= intVal(1, IntMultiplier::Megabytes))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_int_multipliers")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_int_multipliers {
	condition:
		100KB <= filesize and filesize <= 1MB
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithStringOperatorsWorks) {
	auto cond = (matchCount("$1") > intVal(0) && matchLength("$1") > intVal(1) && matchOffset("$1") > intVal(100))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_string_operators")
		.withPlainString("$1", "Hello World!")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_string_operators {
	strings:
		$1 = "Hello World!"
	condition:
		#1 > 0 and !1 > 1 and @1 > 100
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithRegexpWorks) {
	auto cond = stringRef("$1").get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_regexp")
		.withRegexp("$1", R"(md5: [0-9a-zA-Z]{32})", "i")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_regexp {
	strings:
		$1 = /md5: [0-9a-zA-Z]{32}/i
	condition:
		$1
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithRegexpInConditionWorks) {
	auto cond = (id("pe").access("sections")[intVal(0)].access("name").matches(regexp(R"(\.(text|data))", "i")))
		.get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_regexp_in_condition")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withModule("pe")
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(import "pe"

rule rule_with_regexp_in_condition {
	condition:
		pe.sections[0].name matches /\.(text|data)/i
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithConjunctionInConditionWorks) {
	std::vector<YaraExpressionBuilder> terms = { stringRef("$1"), paren(matchOffset("$1") < intVal(100)), paren(entrypoint() == intVal(100)) };
	auto cond = conjunction(terms).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_conjunction")
		.withPlainString("$1", "Hello")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_conjunction {
	strings:
		$1 = "Hello"
	condition:
		$1 and (@1 < 100) and (entrypoint == 100)
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithDisjunctionInConditionWorks) {
	std::vector<YaraExpressionBuilder> terms = { stringRef("$1"), stringRef("$2"), paren(entrypoint() == intVal(100)) };
	auto cond = disjunction(terms).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_disjunction")
		.withPlainString("$1", "Hello")
		.withPlainString("$2", "World")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get();

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_disjunction {
	strings:
		$1 = "Hello"
		$2 = "World"
	condition:
		$1 or $2 or (entrypoint == 100)
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithConjunctionWithLinebreaksInConditionWorks) {
	std::vector<YaraExpressionBuilder> terms = { stringRef("$1"), paren(matchOffset("$1") < intVal(100)), paren(entrypoint() == intVal(100)) };
	auto cond = conjunction(terms, true).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_conjunction_with_linebreaks")
		.withPlainString("$1", "Hello")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get(false);

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_conjunction_with_linebreaks {
	strings:
		$1 = "Hello"
	condition:
		$1 and
		(@1 < 100) and
		(entrypoint == 100)
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithDisjunctionWithLinebreaksInConditionWorks) {
	std::vector<YaraExpressionBuilder> terms = { stringRef("$1"), stringRef("$2"), paren(entrypoint() == intVal(100)) };
	auto cond = disjunction(terms, true).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_disjunction_with_linebreaks")
		.withPlainString("$1", "Hello")
		.withPlainString("$2", "World")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get(false);

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_disjunction_with_linebreaks {
	strings:
		$1 = "Hello"
		$2 = "World"
	condition:
		$1 or
		$2 or
		(entrypoint == 100)
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithParenthesesWithLinebreaksInConditionWorks) {
	auto cond = (stringRef("$1") && paren(stringRef("$2") || stringRef("$3"), true)).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_parentheses_with_linebreaks")
		.withPlainString("$1", "Hello")
		.withPlainString("$2", "Cruel")
		.withPlainString("$3", "World")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withRule(std::move(rule))
		.get(false);

	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(R"(rule rule_with_parentheses_with_linebreaks {
	strings:
		$1 = "Hello"
		$2 = "Cruel"
		$3 = "World"
	condition:
		$1 and (
			$2 or $3
		)
})", yaraFile->getText());
}

TEST_F(BuilderTests,
RuleWithEscapedSequencesWorks) {
	auto cond = (id("pe").access("rich_signature").access("clear_data") == stringVal("DanS\"\t\n\\\x01\xff")).get();

	YaraRuleBuilder newRule;
	auto rule = newRule
		.withName("rule_with_double_quotes")
		.withStringMeta("str_meta", "Double \"\t\n\\\x01\xff quotes")
		.withPlainString("$str", "Double \"\t\n\\\x01\xff quotes")
		.withCondition(cond)
		.get();

	YaraFileBuilder newFile;
	auto yaraFile = newFile
		.withModule("pe")
		.withRule(std::move(rule))
		.get();

	auto expected = R"(import "pe"

rule rule_with_double_quotes {
	meta:
		str_meta = "Double \"\t\n\\\x01\xff quotes"
	strings:
		$str = "Double \"\t\n\\\x01\xff quotes"
	condition:
		pe.rich_signature.clear_data == "DanS\"\t\n\\\x01\xff"
})";
	ASSERT_NE(nullptr, yaraFile);
	EXPECT_EQ(expected, yaraFile->getText());
}

}
}
