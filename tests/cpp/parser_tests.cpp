/**
* @file tests/parser_tests.cpp
* @brief Tests for the YARA parser.
* @copyright AVG Technologies s.r.o, All Rights Reserved
*/

#include <gtest/gtest.h>

#include "yaramod/parser/parser_driver.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/plain_string.h"


using namespace ::testing;

namespace yaramod {
namespace tests {

class ParserTests : public Test
{
public:
	ParserTests() : driver() {}

	void prepareInput(const std::string& inputText)
	{
		input.str(std::string());
		input.clear();
		input << inputText;
		input_text = inputText;
	}

	std::stringstream input;
	std::string input_text;
	ParserDriver driver;
};

TEST_F(ParserTests,
EmptyInputWorks) {
	prepareInput("");

	EXPECT_TRUE(driver.parse(input));
	EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
}

TEST_F(ParserTests,
EmptyRuleWorks) {
	prepareInput(
R"(
rule empty_rule
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("empty_rule", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_EQ(0u, rule->getMetas().size());
	EXPECT_TRUE(rule->getStrings().empty());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RulesWithSameNameForbidden) {
	prepareInput(
R"(
rule same_named_rule {
	condition:
		true
}

rule same_named_rule {
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ("Error at 7.6-20: Redefinition of rule 'same_named_rule'", err.getErrorMessage());
		EXPECT_EQ("{", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}

TEST_F(ParserTests,
RuleWithTagsWorks) {
	prepareInput(
R"(
rule rule_with_tags : Tag1 Tag2 Tag3 {
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_tags", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_EQ(0u, rule->getMetas().size());
	EXPECT_TRUE(rule->getStrings().empty());

	std::vector<std::string> expected_tags = { "Tag1", "Tag2", "Tag3" };
	EXPECT_EQ(expected_tags, rule->getTags());

	std::string expected = R"(
rule rule_with_tags : Tag1 Tag2 Tag3
{
	condition:
		true
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RuleWithMetasWorks) {
	prepareInput(
R"(
rule rule_with_metas
{
	meta:
		str_meta = "string meta"
		int_meta = 42
		bool_meta = true
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_metas", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_TRUE(rule->getStrings().empty());
	ASSERT_EQ(3u, rule->getMetas().size());

	const auto& strMeta = rule->getMetas()[0];
	const auto& intMeta = rule->getMetas()[1];
	const auto& boolMeta = rule->getMetas()[2];

	EXPECT_EQ("str_meta", strMeta.getKey());
	EXPECT_TRUE(strMeta.getValue().isString());
	EXPECT_EQ(R"("string meta")", strMeta.getValue().getText());

	EXPECT_EQ("int_meta", intMeta.getKey());
	EXPECT_TRUE(intMeta.getValue().isInt());
	EXPECT_EQ("42", intMeta.getValue().getText());

	EXPECT_EQ("bool_meta", boolMeta.getKey());
	EXPECT_TRUE(boolMeta.getValue().isBool());
	EXPECT_EQ("true", boolMeta.getValue().getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RuleWithRepetitiveMetasWorks) {
	prepareInput(
R"(
rule rule_with_repetitive_metas
{
	meta:
		author = "me"
		hash = "cryptic"
		hash = "rat"
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_repetitive_metas", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_TRUE(rule->getStrings().empty());
	ASSERT_EQ(3u, rule->getMetas().size());

	const auto& meta1 = rule->getMetas()[0];
	const auto& meta2 = rule->getMetas()[1];
	const auto& meta3 = rule->getMetas()[2];

	EXPECT_EQ("author", meta1.getKey());
	EXPECT_TRUE(meta1.getValue().isString());
	EXPECT_EQ(R"("me")", meta1.getValue().getText());

	EXPECT_EQ("hash", meta2.getKey());
	EXPECT_TRUE(meta2.getValue().isString());
	EXPECT_EQ(R"("cryptic")", meta2.getValue().getText());

	EXPECT_EQ("hash", meta3.getKey());
	EXPECT_TRUE(meta3.getValue().isString());
	EXPECT_EQ(R"("rat")", meta3.getValue().getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexAndDecimalIntegersArePreservedWorks) {
	prepareInput(
R"(
rule hex_and_decimal_integers_are_preserved
{
	meta:
		hex_meta = 0x42
		dec_meta = 42
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_and_decimal_integers_are_preserved", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_TRUE(rule->getStrings().empty());
	ASSERT_EQ(2u, rule->getMetas().size());

	const auto& hexMeta = rule->getMetas()[0];
	const auto& decMeta = rule->getMetas()[1];

	EXPECT_EQ("hex_meta", hexMeta.getKey());
	EXPECT_TRUE(hexMeta.getValue().isInt());
	EXPECT_EQ("0x42", hexMeta.getValue().getText());

	EXPECT_EQ("dec_meta", decMeta.getKey());
	EXPECT_TRUE(decMeta.getValue().isInt());
	EXPECT_EQ("42", decMeta.getValue().getText(true));

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RuleWithVariablesWorks) {
	prepareInput(
R"(
rule rule_with_variables
{
	variables:
		int_var = 25
		float_var = 2.5
		bool_var = true
		string_var = "Hello World!"
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_variables", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_FALSE(rule->getVariables().empty());

	auto variables = rule->getVariables();
	ASSERT_EQ(4u, variables.size());

	auto int_var = variables[0];
	EXPECT_EQ("int_var", int_var.getKey());
	EXPECT_TRUE(int_var.getValue()->isInt());
	EXPECT_EQ("25", int_var.getValue()->getText());

	auto float_var = variables[1];
	EXPECT_EQ("float_var", float_var.getKey());
	EXPECT_TRUE(float_var.getValue()->isFloat());
	EXPECT_EQ("2.5", float_var.getValue()->getText());

	auto bool_var = variables[2];
	EXPECT_EQ("bool_var", bool_var.getKey());
	EXPECT_TRUE(bool_var.getValue()->isBool());
	EXPECT_EQ("true", bool_var.getValue()->getText());

	auto string_var = variables[3];
	EXPECT_EQ("string_var", string_var.getKey());
	EXPECT_TRUE(string_var.getValue()->isString());
	EXPECT_EQ("\"Hello World!\"", string_var.getValue()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
VariableInConditionWorks) {
	prepareInput(
R"(
rule variable_in_condition
{
	variables:
		int_var = 25
	condition:
		int_var > 3
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("variable_in_condition", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_FALSE(rule->getVariables().empty());

	auto variables = rule->getVariables();
	ASSERT_EQ(1u, variables.size());

	ASSERT_TRUE(rule->getCondition()->getFirstTokenIt()->isSymbol());
	ASSERT_EQ(ExpressionType::Int, rule->getCondition()->getFirstTokenIt()->getSymbol()->getDataType());
	ASSERT_EQ("int_var", rule->getCondition()->getFirstTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RuleWithNoStringsDoesntWork) {
	prepareInput(
R"(
rule rule_with_no_strings
{
	strings:
	condition:
		true
}
)");
	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.2-10: Syntax error: Unexpected condition, expected one of string identifier", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
RuleWithPlainTextStringsWorks) {
	prepareInput(
R"(
rule rule_with_plain_strings
{
	strings:
		$1 = "Hello World!"
		$2 = "Bye World."
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_plain_strings", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_FALSE(rule->getStrings().empty());

	auto strings = rule->getStrings();
	ASSERT_EQ(2u, strings.size());

	auto helloWorld = strings[0];
	ASSERT_TRUE(helloWorld->isPlain());
	EXPECT_EQ("$1", helloWorld->getIdentifier());
	EXPECT_EQ("\"Hello World!\"", helloWorld->getText());
	EXPECT_TRUE(static_cast<const PlainString*>(helloWorld)->isAscii());

	auto byeWorld = strings[1];
	ASSERT_TRUE(byeWorld->isPlain());
	EXPECT_EQ("$2", byeWorld->getIdentifier());
	EXPECT_EQ("\"Bye World.\"", byeWorld->getText());
	EXPECT_TRUE(static_cast<const PlainString*>(byeWorld)->isAscii());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
MultipleRulesWorks) {
	prepareInput(
R"(
rule rule_1
{
	strings:
		$1 = "String from Rule 1"
	condition:
		true
}

rule rule_2
{
	strings:
		$1 = "String from Rule 2"
	condition:
		true
}

rule rule_3
{
	strings:
		$1 = "String from Rule 3"
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(3u, driver.getParsedFile().getRules().size());

	std::uint64_t ruleId = 1;
	for (const auto& rule : driver.getParsedFile().getRules())
	{
		std::ostringstream stream;
		stream << "rule_" << ruleId;

		EXPECT_EQ(stream.str(), rule->getName());

		auto strings = rule->getStrings();
		ASSERT_EQ(1u, strings.size());

		auto str = strings[0];
		stream.str(std::string());
		stream.clear();
		stream << "String from Rule " << ruleId;

		ASSERT_TRUE(str->isPlain());
		EXPECT_EQ("$1", str->getIdentifier());
		EXPECT_EQ('"' + stream.str() + '"', str->getText());
		EXPECT_TRUE(static_cast<const PlainString*>(str)->isAscii());

		ruleId++;
	}

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RuleWithPlainTextStringWithModifiersWorks) {
	prepareInput(
R"(
rule rule_with_plain_strings
{
	strings:
		$1 = "Hello World!" nocase wide
		$2 = "Bye World." fullword
		$3 = "string3" base64
		$4 = "string4" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ	LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
		$5 = "string5" base64wide
		$6 = "string6" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ	LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_plain_strings", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(6u, strings.size());

	auto helloWorld = strings[0];
	ASSERT_TRUE(helloWorld->isPlain());
	EXPECT_EQ("$1", helloWorld->getIdentifier());
	EXPECT_EQ("\"Hello World!\" wide nocase", helloWorld->getText());
	EXPECT_FALSE(static_cast<const PlainString*>(helloWorld)->isAscii());
	EXPECT_TRUE(static_cast<const PlainString*>(helloWorld)->isWide());
	EXPECT_TRUE(static_cast<const PlainString*>(helloWorld)->isNocase());
	EXPECT_FALSE(static_cast<const PlainString*>(helloWorld)->isFullword());
	EXPECT_FALSE(static_cast<const PlainString*>(helloWorld)->isBase64());
	EXPECT_FALSE(static_cast<const PlainString*>(helloWorld)->isBase64Wide());

	auto byeWorld = strings[1];
	ASSERT_TRUE(byeWorld->isPlain());
	EXPECT_EQ("$2", byeWorld->getIdentifier());
	EXPECT_EQ("\"Bye World.\" fullword", byeWorld->getText());
	EXPECT_TRUE(static_cast<const PlainString*>(byeWorld)->isAscii());
	EXPECT_FALSE(static_cast<const PlainString*>(byeWorld)->isWide());
	EXPECT_FALSE(static_cast<const PlainString*>(byeWorld)->isNocase());
	EXPECT_TRUE(static_cast<const PlainString*>(byeWorld)->isFullword());
	EXPECT_FALSE(static_cast<const PlainString*>(byeWorld)->isBase64());
	EXPECT_FALSE(static_cast<const PlainString*>(byeWorld)->isBase64Wide());

	auto string3 = strings[2];
	ASSERT_TRUE(string3->isPlain());
	EXPECT_EQ("$3", string3->getIdentifier());
	EXPECT_EQ("\"string3\" base64", string3->getText());
	EXPECT_TRUE(static_cast<const PlainString*>(string3)->isAscii());
	EXPECT_FALSE(static_cast<const PlainString*>(string3)->isWide());
	EXPECT_FALSE(static_cast<const PlainString*>(string3)->isNocase());
	EXPECT_FALSE(static_cast<const PlainString*>(string3)->isFullword());
	EXPECT_TRUE(static_cast<const PlainString*>(string3)->isBase64());
	EXPECT_FALSE(static_cast<const PlainString*>(string3)->isBase64Wide());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
DuplicatedStringModifierForbidden) {
	prepareInput(
R"(
rule duplicated_string_modifier {
	strings:
		$1 = "Hello" wide wide
	condition:
		$1
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.21-24: Duplicated modifier wide", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
InvalidStringModifiersCombination) {
	prepareInput(
R"(
rule invalid_string_modifiers_combination {
	strings:
		$1 = "Hello" base64 nocase
	condition:
		$1
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.23-28: Invalid combination of string modifiers (base64, nocase)", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
MultipleBase64AlphabetsForbidden) {
	prepareInput(
R"(
rule multiple_base64_alphabets {
	strings:
		$1 = "Hello" base64 base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ	LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
	condition:
		$1
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.23-32: Can not specify multiple alphabets for base64 modifiers", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
HexStringWithPlainNibbleWorks) {
	prepareInput(
R"(
rule hex_string_with_plain_nibble
{
	strings:
		$1 = { 11 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_plain_nibble", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 11 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithPlainNibblesWorks) {
	prepareInput(
R"(
rule hex_string_with_plain_nibbles
{
	strings:
		$1 = { 01 23 45 67 89 AB CD EF }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_plain_nibbles", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 45 67 89 AB CD EF }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithLowHighJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_low_high_jump
{
	strings:
		$1 = { 01 23 [5-6] 45 56 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_low_high_jump", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 [5-6] 45 56 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithLowJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_low_jump
{
	strings:
		$1 = { 01 23 [5-] 45 56 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_low_jump", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 [5-] 45 56 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithUnrestrictedJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_unrestricted_jump
{
	strings:
		$1 = { 01 23 [-] 45 56 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_unrestricted_jump", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 [-] 45 56 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithConstantJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_constant_jump
{
	strings:
		$1 = { 01 23 [5] 45 56 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_constant_jump", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 [5] 45 56 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithSimpleOrWorks) {
	prepareInput(
R"(
rule hex_string_with_simple_or
{
	strings:
		$1 = { 01 23 ( AB | CD ) 45 56 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_simple_or", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 ( AB | CD ) 45 56 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithMultibyteSimpleOrWorks) {
	prepareInput(
R"(
rule hex_string_with_multibyte_simple_or
{
	strings:
		$1 = { 01 23 ( AB CD EF | AA BB | EE | FF FF ) 45 56 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_multibyte_simple_or", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 ( AB CD EF | AA BB | EE | FF FF ) 45 56 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithNestedOrWorks) {
	prepareInput(
R"(
rule hex_string_with_nested_or
{
	strings:
		$1 = { 01 23 ( AB ( EE | FF ( 11 | 22 ) FF | ( 11 22 | 33 ) ) | DD ) 45 56 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_nested_or", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 ( AB ( EE | FF ( 11 | 22 ) FF | ( 11 22 | 33 ) ) | DD ) 45 56 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithOrAndJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_or_and_jump
{
	strings:
		$1 = { 01 23 ( AA DD | FF [5-7] FF ) 45 56 }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_or_and_jump", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 ( AA DD | FF [5-7] FF ) 45 56 }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithOrOnTheBeginningAndEnd) {
	prepareInput(
R"(
rule hex_string_with_or_on_the_beginning_and_end
{
	strings:
		$1 = { ( 11 | 22 ) 33 44 ( 55 | 66 ) }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_or_on_the_beginning_and_end", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ ( 11 | 22 ) 33 44 ( 55 | 66 ) }", hexString->getText());

	EXPECT_EQ(TokenType::NEW_LINE, driver.getParsedFile().getTokenStream()->back().getType());
	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithJumpAtBeginningForbidden) {
	prepareInput(
R"(
rule hex_string_with_jump_at_beginning
{
	strings:
		$1 = { [5-6] 11 22 33 }
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.10: Syntax error: Unexpected hex string [, expected one of (, hex string ?, hex string ~, hex string nibble", err.getErrorMessage());
		EXPECT_EQ("[", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}

TEST_F(ParserTests,
HexStringWithJumpAtEndForbidden) {
	prepareInput(
R"(
rule hex_string_with_jump_at_end
{
	strings:
		$1 = { 11 22 33 [5-6] }
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.25: Syntax error: Unexpected }, expected one of (, ), hex string [, hex string |, hex string ?, hex string ~, hex string nibble", err.getErrorMessage());
		EXPECT_EQ("}", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}

TEST_F(ParserTests,
MultipleRulesWithHexStrings) {
	prepareInput(
R"(
rule rule_0
{
	strings:
		$1 = { ( 11 | 22 ) 33 44 ( 55 | 66 ) }
	condition:
		true
}

rule rule_1
{
	strings:
		$1 = { 01 23 ( AA DD | FF [5-7] FF ) 45 56 }
	condition:
		true
}

rule rule_2
{
	strings:
		$1 = { 01 [-] ( AA DD | EE ) }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(3u, driver.getParsedFile().getRules().size());

	for(int i = 0; i < 3; ++i)
	{
		const auto& rule = driver.getParsedFile().getRules()[i];
		std::stringstream name;
		name << "rule_" << i;
		EXPECT_EQ(name.str(), rule->getName());
		EXPECT_EQ("rule", rule->getFirstTokenIt()->getPureText());
		EXPECT_EQ(name.str(), std::next(rule->getFirstTokenIt())->getPureText());
		EXPECT_EQ("}", rule->getLastTokenIt()->getPureText());
		EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
		auto strings = rule->getStrings();
		ASSERT_EQ(1u, strings.size());
		auto hexString = strings[0];
		EXPECT_TRUE(hexString->isHex());
		EXPECT_EQ("$1", hexString->getIdentifier());
		if (i == 0)
			EXPECT_EQ("{ ( 11 | 22 ) 33 44 ( 55 | 66 ) }", hexString->getText());
		else if (i == 1)
			EXPECT_EQ("{ 01 23 ( AA DD | FF [5-7] FF ) 45 56 }", hexString->getText());
		else
			EXPECT_EQ("{ 01 [-] ( AA DD | EE ) }", hexString->getText());
	}

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
InvalidHexStringAtom1) {
	prepareInput(
R"(
rule invalid_hex_string
{
	strings:
	  	$1 = { 01 0X }
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.15: Syntax error: Unknown symbol on input, expected one of hex string ?, hex string nibble", err.getErrorMessage());
		const auto& tokens = driver.getParsedFile().getTokenStream()->getTokensAsText();
		EXPECT_EQ("{", tokens[tokens.size()-4]);
		EXPECT_EQ("0", tokens[tokens.size()-3]);
		EXPECT_EQ("1", tokens[tokens.size()-2]);
		EXPECT_EQ("0", tokens[tokens.size()-1]);
	}
}

TEST_F(ParserTests,
InvalidHexStringAtom2) {
	prepareInput(
R"(
rule invalid_hex_string
{
	strings:
	  	$1 = { 01 0 } }
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.17: Syntax error: Unexpected }, expected one of hex string ?, hex string nibble", err.getErrorMessage());
		EXPECT_EQ("}", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}

TEST_F(ParserTests,
InvalidHexStringOr) {
	prepareInput(
R"(
rule invalid_hex_string
{
	strings:
	  	$1 = { 01 | } }
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.15: Syntax error: Unexpected hex string |, expected one of (, }, hex string [, hex string ?, hex string ~, hex string nibble", err.getErrorMessage());
		EXPECT_EQ("|", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}

TEST_F(ParserTests,
RegexpWithJustCharsWorks) {
	prepareInput(
R"(
rule regexp_with_just_chars
{
	strings:
		$1 = /ab/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_just_chars", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp0 = strings[0];
	EXPECT_TRUE(regexp0->isRegexp());
	EXPECT_EQ("$1", regexp0->getIdentifier());
	EXPECT_EQ("/ab/", regexp0->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithEscapeSequences) {
	prepareInput(
R"(
rule regexp_with_escape_sequences
{
	strings:
		$1 = /http:\/\/someone\.doingevil\.com/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_escape_sequences", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp0 = strings[0];
	EXPECT_TRUE(regexp0->isRegexp());
	EXPECT_EQ("$1", regexp0->getIdentifier());
	EXPECT_EQ("/http:\\/\\/someone\\.doingevil\\.com/", regexp0->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
MultipleRegexpsWithJustCharsWorks) {
	prepareInput(
R"(
rule regexp_with_just_chars
{
	strings:
		$1 = /a/
		$2 = /ab/
		$3 = /abc/
		$4 = /abcd/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_just_chars", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(4u, strings.size());

	auto regexp0 = strings[0];
	EXPECT_TRUE(regexp0->isRegexp());
	EXPECT_EQ("$1", regexp0->getIdentifier());
	EXPECT_EQ("/a/", regexp0->getText());
	auto regexp1 = strings[1];
	EXPECT_TRUE(regexp1->isRegexp());
	EXPECT_EQ("$2", regexp1->getIdentifier());
	EXPECT_EQ("/ab/", regexp1->getText());
	auto regexp2 = strings[2];
	EXPECT_TRUE(regexp2->isRegexp());
	EXPECT_EQ("$3", regexp2->getIdentifier());
	EXPECT_EQ("/abc/", regexp2->getText());
	auto regexp3 = strings[3];
	EXPECT_TRUE(regexp3->isRegexp());
	EXPECT_EQ("$4", regexp3->getIdentifier());
	EXPECT_EQ("/abcd/", regexp3->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpLimitedToWholeLineWorks) {
	prepareInput(
R"(
rule regexp_limited_to_whole_line
{
	strings:
		$1 = /^abcd$/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_limited_to_whole_line", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ("/^abcd$/", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithPredefinedClassesWorks) {
	prepareInput(
R"(
rule regexp_with_predefined_classes
{
	strings:
		$1 = /\w\W\s\S\d\D\babc\B/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_predefined_classes", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/\w\W\s\S\d\D\babc\B/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithCustomClassWorks) {
	prepareInput(
R"(
rule regexp_with_custom_class
{
	strings:
		$1 = /abc[xyz]def/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_custom_class", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/abc[xyz]def/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithCustomNegativeClassWorks) {
	prepareInput(
R"(
rule regexp_with_custom_negative_class
{
	strings:
		$1 = /abc[^xyz]def/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_custom_negative_class", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/abc[^xyz]def/)", regexp->getText());

	EXPECT_EQ("true", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("true", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithOptionalEscapedCharsWorks) {
	prepareInput(
R"(
rule regexp_with_optional_escaped_chars
{
	strings:
		$1 = /1\x32?3/
	condition:
		$1
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_optional_escaped_chars", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/1\x32?3/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithEscapedSquareBracketsInsideClassWorks) {
	prepareInput(
R"(
rule regexp_with_escaped_square_brackets_inside_class
{
	strings:
		$1 = /[\[\]++]/
	condition:
		$1
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_escaped_square_brackets_inside_class", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/[\[\]++]/)", regexp->getText());

	EXPECT_EQ("$1", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("$1", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithUnescapedSquareBracketsInsideClassWorks) {
	prepareInput(
R"(
rule regexp_with_unescaped_square_brackets_inside_class
{
	strings:
		$1 = /[ [\]{}*+,\/]{2,6}OUTSIDE[ [\]{}*+?@|_]OUTSIDE/
		$2 = /[ !#()[\]{}*][ !#[\]+_]/
		$3 = /[[\]*+]/
		$4 = /[\[\]*+]/
	condition:
		all of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_unescaped_square_brackets_inside_class", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(4u, strings.size());

	auto regexp1 = strings[0];
	EXPECT_TRUE(regexp1->isRegexp());
	EXPECT_EQ("$1", regexp1->getIdentifier());
	EXPECT_EQ(R"(/[ [\]{}*+,\/]{2,6}OUTSIDE[ [\]{}*+?@|_]OUTSIDE/)", regexp1->getText());

	auto regexp2 = strings[1];
	EXPECT_TRUE(regexp2->isRegexp());
	EXPECT_EQ("$2", regexp2->getIdentifier());
	EXPECT_EQ(R"(/[ !#()[\]{}*][ !#[\]+_]/)", regexp2->getText());

	auto regexp3 = strings[2];
	EXPECT_TRUE(regexp3->isRegexp());
	EXPECT_EQ("$3", regexp3->getIdentifier());
	EXPECT_EQ(R"(/[[\]*+]/)", regexp3->getText());

	auto regexp = strings[3];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$4", regexp->getIdentifier());
	EXPECT_EQ(R"(/[\[\]*+]/)", regexp->getText());

	EXPECT_EQ("all", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("them", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithEmptyAlternationGroupWorks) {
	prepareInput(
R"(
rule regexp_with_empty_alternation_group
{
	strings:
		$1 = /(a|b|)/
	condition:
		all of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_empty_alternation_group", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp1 = strings[0];
	EXPECT_TRUE(regexp1->isRegexp());
	EXPECT_EQ("$1", regexp1->getIdentifier());
	EXPECT_EQ(R"(/(a|b|)/)", regexp1->getText());

	EXPECT_EQ("all", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("them", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
InvalidCuckooRuleAccessTokenStream) {
	prepareInput(
R"(
import "cuckoo"

rule invalid_hex_string
{
	condition:
		cuckoo.
		filesystem.
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 9.1: Syntax error: Unexpected }, expected one of identifier", err.getErrorMessage());
		const auto& tokens = driver.getParsedFile().getTokenStream()->getTokensAsText();
		EXPECT_EQ("cuckoo", tokens[tokens.size()-7]);
		EXPECT_EQ(".", tokens[tokens.size()-6]);
		EXPECT_EQ("\n", tokens[tokens.size()-5]);
		EXPECT_EQ("filesystem", tokens[tokens.size()-4]);
		EXPECT_EQ(".", tokens[tokens.size()-3]);
		EXPECT_EQ("\n", tokens[tokens.size()-2]);
		EXPECT_EQ("}", tokens[tokens.size()-1]);
	}
}

TEST_F(ParserTests,
ComplicatedRegexpClassWorks) {
	prepareInput(
R"(
import "cuckoo"
import "pe"

rule rule_with_complicated_regexp_class
{
	condition:
		cuckoo.network.http_get(/[^\\]+/)
		and
		cuckoo.filesystem.file_access(/\.bribe$/)
		and
		cuckoo.filesystem.file_access(/[\]}]\.(b[0-2]+|VC[0-9]*|DAQ)$/)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_complicated_regexp_class", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	EXPECT_EQ("cuckoo.network.http_get(/[^\\\\]+/) and cuckoo.filesystem.file_access(/\\.bribe$/) and cuckoo.filesystem.file_access(/[\\]}]\\.(b[0-2]+|VC[0-9]*|DAQ)$/)", rule->getCondition()->getText());
	EXPECT_EQ("cuckoo", rule->getCondition()->getFirstTokenIt()->getText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	std::string expected = R"(
import "cuckoo"
import "pe"

rule rule_with_complicated_regexp_class
{
	condition:
		cuckoo.network.http_get(/[^\\]+/) and
		cuckoo.filesystem.file_access(/\.bribe$/) and
		cuckoo.filesystem.file_access(/[\]}]\.(b[0-2]+|VC[0-9]*|DAQ)$/)
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}


TEST_F(ParserTests,
RegexpWithIterationWorks) {
	prepareInput(
R"(
rule regexp_with_iteration
{
	strings:
		$1 = /ab*c/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_iteration", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/ab*c/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithPositiveIterationWorks) {
	prepareInput(
R"(
rule regexp_with_positive_iteration
{
	strings:
		$1 = /ab+c/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_positive_iteration", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/ab+c/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithOptionalWorks) {
	prepareInput(
R"(
rule regexp_with_optional
{
	strings:
		$1 = /ab?c/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_optional", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/ab?c/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithRangesWorks) {
	prepareInput(
R"(
rule regexp_with_ranges
{
	strings:
		$1 = /a{5}b{2,3}c{4,}d{,5}/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_ranges", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/a{5}b{2,3}c{4,}d{,5}/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithGreedyOperatorsWorks) {
	prepareInput(
R"(
rule regexp_with_greedy_operators
{
	strings:
		$1 = /a*?b+?c??d{5,6}?/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_greedy_operators", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/a*?b+?c??d{5,6}?/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithGroupsWorks) {
	prepareInput(
R"(
rule regexp_with_groups
{
	strings:
		$1 = /ab(cd(ef)gh(i))/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_groups", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/ab(cd(ef)gh(i))/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithOrWorks) {
	prepareInput(
R"(
rule regexp_with_or
{
	strings:
		$1 = /(abc|def|xyz)/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_or", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ(R"(/(abc|def|xyz)/)", regexp->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithModifiersWorks) {
	prepareInput(
R"(
rule regexp_with_modifiers
{
	strings:
		$1 = /(abc|def|xyz)/ wide
		$2 = /(abc|def|xyz)/ nocase fullword
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_modifiers", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(2u, strings.size());

	auto regexp1 = strings[0];
	EXPECT_TRUE(regexp1->isRegexp());
	EXPECT_EQ("$1", regexp1->getIdentifier());
	EXPECT_EQ(R"(/(abc|def|xyz)/ wide)", regexp1->getText());

	auto regexp2 = strings[1];
	EXPECT_TRUE(regexp2->isRegexp());
	EXPECT_EQ("$2", regexp2->getIdentifier());
	EXPECT_EQ(R"(/(abc|def|xyz)/ nocase fullword)", regexp2->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithUndefinedRangeForbidden) {
	prepareInput(
R"(
rule regexp_with_undefined_range
{
	strings:
		$1 = /ab{,}/
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
 		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.14: Range in regular expression does not have defined lower bound nor higher bound", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
RegexpWithInvalidRangeForbidden) {
	prepareInput(
R"(
rule regexp_with_invalid_range
{
	strings:
		$1 = /ab{6,5}/
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
 		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.16: Range in regular expression has greater lower bound than higher bound", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
RulesWithVariablesAndStringsWork) {
	prepareInput(
R"(rule rule1
{
	strings:
		$string = "Hello World!"
		$anotherstring = "Hello World! 2"
	variables:
		integer = 23
		string = "Not a Hello World!"
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

std::string expected = R"(rule rule1
{
	strings:
		$string = "Hello World!"
		$anotherstring = "Hello World! 2"
	variables:
		integer = 23
		string = "Not a Hello World!"
	condition:
		true
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RuleWithUnorderedSections) {
	prepareInput(
R"(rule rule1
{
	variables:
		var = 23
	strings:
		$1 = "Hello World!"
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

std::string expected = R"(rule rule1
{
	variables:
		var = 23
	strings:
		$1 = "Hello World!"
	condition:
		true
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
GlobalRuleModifierWorks) {
	prepareInput(
R"(
global rule global_rule
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("global_rule", rule->getName());
	EXPECT_EQ(Rule::Modifier::Global, rule->getModifier());
	EXPECT_FALSE(rule->isPrivate());
	EXPECT_TRUE(rule->isGlobal());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
PrivateRuleModifierWorks) {
	prepareInput(
R"(
private rule private_rule
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("private_rule", rule->getName());
	EXPECT_EQ(Rule::Modifier::Private, rule->getModifier());
	EXPECT_TRUE(rule->isPrivate());
	EXPECT_FALSE(rule->isGlobal());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
PrivateGlobalRuleModifierWorks) {
	prepareInput(
R"(
private global rule private_global_rule
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("private_global_rule", rule->getName());
	EXPECT_EQ(Rule::Modifier::PrivateGlobal, rule->getModifier());
	EXPECT_TRUE(rule->isPrivate());
	EXPECT_TRUE(rule->isGlobal());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
SetRuleModifierWorks) {
	prepareInput(
R"(
rule rule1
{
	condition:
		true
}

rule rule2
{
	condition:
		true
}

rule rule3
{
	condition:
		true
}

rule rule4
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(4u, driver.getParsedFile().getRules().size());

	const auto& rule1 = driver.getParsedFile().getRules()[0];
	const auto& rule2 = driver.getParsedFile().getRules()[1];
	const auto& rule3 = driver.getParsedFile().getRules()[2];
	const auto& rule4 = driver.getParsedFile().getRules()[3];
	rule1->setModifier(Rule::Modifier::None);
	rule2->setModifier(Rule::Modifier::Private);
	rule3->setModifier(Rule::Modifier::Global);
	rule4->setModifier(Rule::Modifier::PrivateGlobal);

	EXPECT_EQ(Rule::Modifier::None, rule1->getModifier());
	EXPECT_EQ(Rule::Modifier::Private, rule2->getModifier());
	EXPECT_EQ(Rule::Modifier::Global, rule3->getModifier());
	EXPECT_EQ(Rule::Modifier::PrivateGlobal, rule4->getModifier());
	EXPECT_FALSE(rule1->isPrivate());
	EXPECT_FALSE(rule1->isGlobal());
	EXPECT_TRUE(rule2->isPrivate());
	EXPECT_FALSE(rule2->isGlobal());
	EXPECT_FALSE(rule3->isPrivate());
	EXPECT_TRUE(rule3->isGlobal());
	EXPECT_TRUE(rule4->isPrivate());
	EXPECT_TRUE(rule4->isGlobal());

	std::string expected = R"(
rule rule1
{
	condition:
		true
}

private rule rule2
{
	condition:
		true
}

global rule rule3
{
	condition:
		true
}

private global rule rule4
{
	condition:
		true
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
SetRuleModifierWorksWithDeleting) {
	prepareInput(
R"(
private rule rule1
{
	condition:
		true
}

global rule rule2
{
	condition:
		true
}

global rule rule3
{
	condition:
		true
}

private global rule rule4
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(4u, driver.getParsedFile().getRules().size());

	const auto& rule1 = driver.getParsedFile().getRules()[0];
	const auto& rule2 = driver.getParsedFile().getRules()[1];
	const auto& rule3 = driver.getParsedFile().getRules()[2];
	const auto& rule4 = driver.getParsedFile().getRules()[3];
	rule1->setModifier(Rule::Modifier::None);
	rule2->setModifier(Rule::Modifier::Private);
	rule3->setModifier(Rule::Modifier::PrivateGlobal);
	rule4->setModifier(Rule::Modifier::Global);

	EXPECT_EQ(Rule::Modifier::None, rule1->getModifier());
	EXPECT_EQ(Rule::Modifier::Private, rule2->getModifier());
	EXPECT_EQ(Rule::Modifier::PrivateGlobal, rule3->getModifier());
	EXPECT_EQ(Rule::Modifier::Global, rule4->getModifier());
	EXPECT_FALSE(rule1->isPrivate());
	EXPECT_FALSE(rule1->isGlobal());
	EXPECT_TRUE(rule2->isPrivate());
	EXPECT_FALSE(rule2->isGlobal());
	EXPECT_TRUE(rule3->isPrivate());
	EXPECT_TRUE(rule3->isGlobal());
	EXPECT_FALSE(rule4->isPrivate());
	EXPECT_TRUE(rule4->isGlobal());

	std::string expected = R"(
rule rule1
{
	condition:
		true
}

private rule rule2
{
	condition:
		true
}

private global rule rule3
{
	condition:
		true
}

global rule rule4
{
	condition:
		true
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ImportWorks) {
	prepareInput(
R"(
import "pe"

rule dummy_rule
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	EXPECT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(1u, driver.getParsedFile().getImports().size());
	EXPECT_EQ("pe", driver.getParsedFile().getImports()[0]->getName());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ImportOfUnrecognizedModuleForbidden) {
	prepareInput(
R"(
import "module"

rule dummy_rule
{
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		ASSERT_EQ(0u, driver.getParsedFile().getImports().size());
		EXPECT_EQ("Error at 2.8-15: Unrecognized module 'module' imported", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
TrueConditionWorks) {
	prepareInput(
R"(
rule true_condition
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("true", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
FalseConditionWorks) {
	prepareInput(
R"(
rule false_condition
{
	condition:
		false
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("false", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringIdConditionWorks) {
	prepareInput(
R"(
rule string_id_condition
{
	strings:
		$1 = "Hello World!"
	condition:
		$1
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$1", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringAtEntryPointConditionWorks) {
	prepareInput(
R"(
rule string_at_entrypoint_condition
{
	strings:
		$1 = "Hello World!"
	condition:
		$1 at entrypoint
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$1 at entrypoint", rule->getCondition()->getText());
	EXPECT_EQ("$1", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("entrypoint", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringInRangeConditionWorks) {
	prepareInput(
R"(
rule string_in_range_condition
{
	strings:
		$1 = "Hello World!"
	condition:
		$1 in (10 .. 20)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$1 in (10 .. 20)", rule->getCondition()->getText());
	EXPECT_EQ("$1", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringInRangeConditionWorks2) {
	prepareInput(
R"(
rule string_in_range_condition2
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		$a in (0 .. 100) and
		$b in (100 .. filesize)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$a in (0 .. 100) and $b in (100 .. filesize)", rule->getCondition()->getText());
	EXPECT_EQ("$a", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
NotConditionWorks) {
	prepareInput(
R"(
rule not_condition
{
	condition:
		not true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("not true", rule->getCondition()->getText());
	EXPECT_EQ("not", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("true", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AndConditionWorks) {
	prepareInput(
R"(
rule and_condition
{
	condition:
		true and
		not false
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("true and not false", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}


TEST_F(ParserTests,
AndConditionWorks2) {
	prepareInput(
R"(
rule and_condition
{
	strings:
		$1 = "Hello World!"
		$2 = "Bye World."
	condition:
		$1 and
		$2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$1 and $2", rule->getCondition()->getText());
	EXPECT_EQ("$1", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("$2", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
OrConditionWorks) {
	prepareInput(
R"(
rule or_condition
{
	condition:
		true or
		not false
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("true or not false", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
EscapedOrConditionWorks) {
	prepareInput(
R"(
rule or_condition
{
	condition:
		true or
		not false or
		false
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("true or not false or false", rule->getCondition()->getText());
	EXPECT_EQ("true", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("false", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RelationalConditionWorks) {
	prepareInput(
R"(
rule relational_condition
{
	condition:
		filesize < 10 or
		filesize > 20 or
		filesize <= 10 or
		filesize >= 20 or
		filesize != 15 or
		filesize == 16
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("filesize < 10 or filesize > 20 or filesize <= 10 or filesize >= 20 or filesize != 15 or filesize == 16", rule->getCondition()->getText());
	EXPECT_EQ("filesize", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("16", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParenthesesConditionWorks) {
	prepareInput(
R"(
rule relational_condition
{
	strings:
		$1 = "Hello World"
	condition:
		($1 at (entrypoint)) and
		(filesize > 100)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("($1 at (entrypoint)) and (filesize > 100)", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ArithmeticOpConditionWorksSimple) {
	prepareInput(
R"(
rule arithmetic_op_condition
{
	condition:
		(10 + 20 < 200 - 100)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((10 + 20 < 200 - 100))", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ArithmeticOpConditionWorks) {
	prepareInput(
R"(
rule arithmetic_op_condition
{
	condition:
		(10 + 20 < 200 - 100) and
		(10 * 20 > 20 \ 10) and
		(10 % 2) and
		(-5)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((10 + 20 < 200 - 100) and (10 * 20 > 20 \ 10) and (10 % 2) and (-5))", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ArithmeticOpConditionWorks2) {
	prepareInput(
R"(
rule rule_with_arithmetic_operations
{
	condition:
		(entrypoint + 100 * 3) < (filesize - 100 \ 2)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((entrypoint + 100 * 3) < (filesize - 100 \ 2))", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
BitwiseOpConditionNegation) {
	prepareInput(
R"(
rule bitwise_op_condition_negation
{
	condition:
		(~2 == 0)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((~2 == 0))", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
BitwiseOpConditionWorks) {
	prepareInput(
R"(
rule bitwise_op_condition
{
	condition:
		(3 & 2 == 2) and
		(7 ^ 7 == 0) and
		(3 | 4 == 7) and
		(~5) and
		(8 >> 2 == 2) and
		(1 << 3 == 8)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((3 & 2 == 2) and (7 ^ 7 == 0) and (3 | 4 == 7) and (~5) and (8 >> 2 == 2) and (1 << 3 == 8))", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
IntFunctionConditionWorks) {
	prepareInput(
R"(
rule int_function_condition
{
	condition:
		int8(uint32(int32be(5))) == 64
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("int8(uint32(int32be(5))) == 64", rule->getCondition()->getText());
	EXPECT_EQ("int8", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("64", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
DoubleInConditionWorks) {
	prepareInput(
R"(
rule double_in_condition
{
	condition:
		1.23 + 4.56 > 10.5
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("1.23 + 4.56 > 10.5", rule->getCondition()->getText());
	EXPECT_EQ("1.23", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("10.5", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ContainsInConditionWorks) {
	prepareInput(
R"(
rule contains_in_condition
{
	condition:
		"Hello" contains "Hell"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"("Hello" contains "Hell")", rule->getCondition()->getText());
	EXPECT_EQ("\"Hello\"", rule->getCondition()->getFirstTokenIt()->getText());
	EXPECT_EQ("\"Hell\"", rule->getCondition()->getLastTokenIt()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
MatchesInConditionWorks) {
	prepareInput(
R"(
rule matches_in_condition
{
	condition:
		"Hello" matches /^Hell.*$/
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"("Hello" matches /^Hell.*$/)", rule->getCondition()->getText());
	EXPECT_EQ("\"Hello\"", rule->getCondition()->getFirstTokenIt()->getText());
	EXPECT_EQ("/", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}


TEST_F(ParserTests,
StringCountConditionWorks) {
	prepareInput(
R"(
rule string_count_condition
{
	strings:
		$1 = "Hello World"
	condition:
		#1 == 5
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("#1 == 5", rule->getCondition()->getText());
	EXPECT_EQ("\"#1\"", rule->getCondition()->getFirstTokenIt()->getText());
	EXPECT_EQ("5", rule->getCondition()->getLastTokenIt()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringOffsetConditionWorks) {
	prepareInput(
R"(
rule string_offset_condition
{
	strings:
		$1 = "Hello World"
		$2 = "Hello World2"
	condition:
		(@1 > 5) and
		(@2[0] > 100)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(@1 > 5) and (@2[0] > 100)", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexadecimalNumbersInConditionWorks) {
	prepareInput(
R"(
rule string_offset_condition
{
	strings:
		$1 = "Hello World"
		$2 = "Hello World2"
	condition:
		(@1 > 0x1000) and
		(@2[0x11] > 0x14)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(@1 > 0x1000) and (@2[0x11] > 0x14)", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringLengthConditionWorks) {
	prepareInput(
R"(
rule string_length_condition
{
	strings:
		$1 = "Hello World"
	condition:
		(!1 > 0) and
		(!1[1] > 100)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(!1 > 0) and (!1[1] > 100)", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
FunctionCallConditionWorks) {
	prepareInput(
R"(
import "pe"

rule function_call_condition
{
	condition:
		(pe.is_dll()) and
		(pe.section_index(".text") == 0)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((pe.is_dll()) and (pe.section_index(".text") == 0))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StructureAccessConditionWorks) {
	prepareInput(
R"(
import "pe"

rule structure_access_condition
{
	condition:
		(pe.linker_version.major > 0) and
		(pe.linker_version.minor > 0)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(pe.linker_version.major > 0) and (pe.linker_version.minor > 0)", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ArrayAccessConditionWorks1) {
	prepareInput(
R"(
import "pe"

rule array_access_condition
{
	condition:
		pe.sections[0].name == ".text"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	auto condition = rule->getCondition();
	EXPECT_EQ(R"(pe.sections[0].name == ".text")", condition->getText());
	EXPECT_EQ("pe", condition->getFirstTokenIt()->getPureText());
	EXPECT_EQ(".text", condition->getLastTokenIt()->getPureText());

	auto expEq = std::static_pointer_cast<const EqExpression>(condition);
	auto expLeft = std::static_pointer_cast<const StructAccessExpression>(expEq->getLeftOperand());
	EXPECT_EQ("pe", expLeft->getFirstTokenIt()->getPureText());
	EXPECT_EQ("name", expLeft->getLastTokenIt()->getPureText());

	auto expArrayAccess = std::static_pointer_cast<const ArrayAccessExpression>(expLeft->getStructure());
	EXPECT_EQ("pe", expArrayAccess->getFirstTokenIt()->getPureText());
	EXPECT_EQ("]", expArrayAccess->getLastTokenIt()->getPureText());

	auto expAccessor = expArrayAccess->getAccessor();
	EXPECT_EQ("0", expAccessor->getFirstTokenIt()->getPureText());
	EXPECT_EQ("0", expAccessor->getLastTokenIt()->getPureText());
	auto expArray = std::static_pointer_cast<const StructAccessExpression>(expArrayAccess->getArray());
	EXPECT_EQ("pe", expArray->getFirstTokenIt()->getPureText());
	EXPECT_EQ("sections", expArray->getLastTokenIt()->getPureText());

	auto expStruct = std::static_pointer_cast<const IdExpression>(expArray->getStructure());
	EXPECT_EQ("pe", expStruct->getFirstTokenIt()->getPureText());
	EXPECT_EQ("pe", expStruct->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ArrayAccessConditionWorks2) {
	prepareInput(
R"(
import "pe"

rule array_access_condition
{
	condition:
		(pe.number_of_sections > 0) and
		(pe.sections[0].name == ".text")
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((pe.number_of_sections > 0) and (pe.sections[0].name == ".text"))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForIntegerSetConditionWorks) {
	prepareInput(
R"(
rule for_integer_set_condition
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		for all i in (1, 2, 3) : ( @a[i] + 10 == @b[i] )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for all i in (1, 2, 3) : ( @a[i] + 10 == @b[i] )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForArrayConditionWorks) {
	prepareInput(
R"(
import "pe"

rule for_array_condition
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		for any section in pe.sections : ( section.name == ".text" )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any section in pe.sections : ( section.name == \".text\" )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
NestedForArrayConditionWorks) {
	prepareInput(
R"(
import "macho"

rule nested_for_array_condition
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		for any segment in macho.segments : (
			for any section in segment.sections : (
				section.sectname == ".text"
			)
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any segment in macho.segments : ( for any section in segment.sections : ( section.sectname == \".text\" ) )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
UserDefinedArrayWorks) {
	prepareInput(
R"(
import "cuckoo"

rule user_defined_array
{
	condition:
		1 of [cuckoo.sync.mutex(/a/),
			cuckoo.sync.mutex(/b/)]
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected = R"(
import "cuckoo"

rule user_defined_array
{
	condition:
		1 of [
			cuckoo.sync.mutex(/a/),
			cuckoo.sync.mutex(/b/)
		]
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForDictConditionWorks) {
	prepareInput(
R"(
import "pe"

rule for_dict_condition
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		for any k, v in pe.version_info : (
			k == "CompanyName" and
			v contains "Microsoft"
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any k, v in pe.version_info : ( k == \"CompanyName\" and v contains \"Microsoft\" )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForStringSetConditionWorks) {
	prepareInput(
R"(
rule for_string_set_condition
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		for any of ($a, $b) : ( $ at entrypoint )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any of ($a, $b) : ( $ at entrypoint )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForStringLiteralSetConditionWorks) {
	prepareInput(
R"(
import "pe"

rule for_string_literal_set_condition
{
	condition:
		for any s in ("hash1", "hash2", "hash3") : ( pe.imphash() == s )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any s in (\"hash1\", \"hash2\", \"hash3\") : ( pe.imphash() == s )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForStringLiteralSetWithOneStringConditionWorks) {
	prepareInput(
R"(
import "pe"

rule for_string_literal_set_condition
{
	condition:
		for any s in ("hash1") : ( pe.imphash() == s )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any s in (\"hash1\") : ( pe.imphash() == s )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForStringLiteralSetWithStringSymbolsConditionWorks) {
	prepareInput(
R"(
import "pe"
import "elf"

rule for_string_literal_set_condition
{
	condition:
		for any s in ("hash1", elf.dynsym [ 0 ].name, pe.imphash ( )) : ( "abc123" == s )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any s in (\"hash1\", elf.dynsym[0].name, pe.imphash()) : ( \"abc123\" == s )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(R"(
import "pe"
import "elf"

rule for_string_literal_set_condition
{
	condition:
		for any s in ("hash1", elf.dynsym[0].name, pe.imphash()) : ( "abc123" == s )
}
)", driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForExpressionSetWithItemsVariousTypesForbidden) {
	prepareInput(
R"(
import "pe"

rule for_string_literal_set_condition
{
	condition:
		for any s in ("hash1", 1, "hash3") : ( pe.imphash() == s )
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 7.27: all items in enumeration must be same type", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
NegativeMetaValuesWorks) {
	prepareInput(
R"(
rule rule_with_negative_meta
{
	meta:
		negative_value = -123
		positive_value = 456
		string_value = "test"
		bool_value = true
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	const auto& metas = rule->getMetas();
	ASSERT_EQ(4u, metas.size());

	EXPECT_EQ("negative_value", metas[0].getKey());
	EXPECT_EQ("-123", metas[0].getValue().getPureText());

	EXPECT_EQ("positive_value", metas[1].getKey());
	EXPECT_EQ("456", metas[1].getValue().getPureText());

	EXPECT_EQ("string_value", metas[2].getKey());
	EXPECT_EQ("test", metas[2].getValue().getPureText());

	EXPECT_EQ("bool_value", metas[3].getKey());
	EXPECT_EQ("true", metas[3].getValue().getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForExpressionInOverStringSet) {
	prepareInput(
R"(
rule expression_in_over_string_set
{
	condition:
		for any i in ("abc", "def") : ( i contains "string" )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(for any i in ("abc", "def") : ( i contains "string" ))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForExpressionInOverIntegerRange) {
	prepareInput(
R"(
rule expression_in_over_integer_range
{
	condition:
		for any i in (0 .. 0x1500) : ( uint32(i) == 0x00004550 )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(for any i in (0 .. 0x1500) : ( uint32(i) == 0x00004550 ))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForOfWithStringLiteralsForbidden) {
	prepareInput(
R"(
rule for_of_with_string_literals_forbidden
{
	condition:
		for any of ("hash1", "hash2", "hash3") : ( true )
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.15-21: Syntax error: Unexpected \", expected one of string identifier, string wildcard", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
NoneOfThemConditionWorks) {
	prepareInput(
R"(
rule none_of_string_set_condition
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		none of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("none of them", rule->getCondition()->getText());
	EXPECT_EQ("none", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("them", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
NoneOfSetConditionWorks) {
	prepareInput(
R"(
rule none_of_string_set_condition
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		none of ($a, $b)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("none of ($a, $b)", rule->getCondition()->getText());
	EXPECT_EQ("none", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
OfConditionWorks) {
	prepareInput(
R"(
rule of_condition
{
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		1 of ($a, $b)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("1 of ($a, $b)", rule->getCondition()->getText());
	EXPECT_EQ("1", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
OfAtConditionWorks) {
	prepareInput(
R"(
rule of_condition
{
	strings:
		$a = "dummy1"
		$b = /dummy\d/
	condition:
		any of them at 0
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("any of them at 0", rule->getCondition()->getText());
	EXPECT_EQ("any", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("0", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
OfAtWithStringSetConditionWorks) {
	prepareInput(
R"(
rule of_condition
{
	strings:
		$a = "dummy1"
		$b = /dummy\d/
	condition:
		1 of ($a, $b) at 3
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("1 of ($a, $b) at 3", rule->getCondition()->getText());
	EXPECT_EQ("1", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("3", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
OfWithStringSetAndAtWithExpressionConditionWorks) {
	prepareInput(
R"(
rule of_condition
{
	strings:
		$a = "dummy1"
		$b = /dummy\d/
	condition:
		any of ($a, $b) at filesize - 10
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("any of ($a, $b) at filesize - 10", rule->getCondition()->getText());
	EXPECT_EQ("any", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("10", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
EmptyStringMetaValue) {
	prepareInput(
R"(
import "pe"

rule rule_name
{
	meta:
		author = ""
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_TRUE(rule->getMetas()[0].getValue().isString());
	EXPECT_EQ(R"("")", rule->getMetas()[0].getValue().getText());
	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
EmptyPlainStringValue) {
	prepareInput(
R"(
import "pe"

rule rule_name
{
	meta:
		author = "Mr. Avastian"
	strings:
		$s1 = ""
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$s1", rule->getStrings()[0]->getIdentifier());
	EXPECT_EQ(R"("")", rule->getStrings()[0]->getText());
	EXPECT_EQ("", rule->getStrings()[0]->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
EmptyStringInConditionWorks) {
	prepareInput(
R"(
import "pe"

rule rule_name
{
	meta:
		author = "Mr. Avastian"
	condition:
		(pe.sections[0].name == "EmptyString" or pe.sections[0].name == "")
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(pe.sections[0].name == \"EmptyString\" or pe.sections[0].name == \"\")", rule->getCondition()->getText());
	EXPECT_EQ("(", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	std::string expected = R"(
import "pe"

rule rule_name
{
	meta:
		author = "Mr. Avastian"
	condition:
		(
			pe.sections[0].name == "EmptyString" or
			pe.sections[0].name == ""
		)
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringsAndArithmeticOperationsForbidden) {
	prepareInput(
R"(
rule strings_and_arithmetic_operations
{
	condition:
		10 + "hello"
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.6: operator '+' expects integer or float on the right-hand side", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
BoolAndArithmeticOperationsForbidden) {
	prepareInput(
R"(
rule bool_and_arithmetic_operations
{
	condition:
		10 + true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.8-11: Syntax error: Unexpected true, expected one of -, ~, (, /, entrypoint, filesize, integer, \", fixed-width integer function, string count, string offset, string length, identifier, float", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
ContainsAndNonStringForbidden) {
	prepareInput(
R"(
rule contains_and_non_string
{
	condition:
		"abc" contains 5
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.9-16: operator 'contains' expects string on the right-hand side of the expression", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
UndefinedStringReferenceForbidden) {
	prepareInput(
R"(
rule contains_and_non_string {
	strings:
		$1 = "Hello"
	condition:
		$2
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 6.3-4: Reference to undefined string '$2'", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
StringWildcardConditionWorks) {
	prepareInput(
R"(
rule string_wildcard_condition
{
	strings:
		$aaa = "dummy1"
		$aab = "dummy2"
		$bbb = "dummy3"
	condition:
		for any of ($aa*, $bbb) : ( $ )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any of ($aa*, $bbb) : ( $ )", rule->getCondition()->getText());
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringWildcardConditionWithNoMatchingStringForbidden) {
	prepareInput(
R"(
rule string_wildcard_condition_with_no_matching_string
{
	strings:
		$aaa = "dummy1"
		$aab = "dummy2"
		$bbb = "dummy3"
	condition:
		for any of ($c*) : ( $ )
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 9.15-17: No string matched with wildcard '$c*'", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
SameVariableInNestedForLoopsForbidden) {
	prepareInput(
R"(
rule same_variable_in_nested_for_loops
{
	strings:
		$1 = "hello"
	condition:
		for all i in (1..5) : ( for any i in (10 .. 15) : ( $1 at i ) )
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 7.35: Redefinition of identifier 'i'", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
FloatValueWorks) {
	prepareInput(
R"(
rule rule_with_float_value_in_condition
{
	condition:
		0.8699322552472 == 0.8699322552472
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(0.8699322552472 == 0.8699322552472)", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
FloatValueWorks2) {
	prepareInput(
R"(
rule rule_with_float_value_in_condition
{
	condition:
		0.0000000001 == 0.0000000001
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(0.0000000001 == 0.0000000001)", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ConsoleModuleWorks) {
	prepareInput(
R"(
import "console"

rule console_module
{
	condition:
		console.log("Hello") and
		console.log("32bits at 0: ", uint32(0))
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(console.log("Hello") and console.log("32bits at 0: ", uint32(0)))", rule->getCondition()->getText());
	EXPECT_EQ("console", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
CuckooModuleWorks) {
	prepareInput(
R"(
import "cuckoo"

rule cuckoo_module
{
	strings:
		$some_string = { 01 02 03 04 05 05 }
	condition:
		$some_string and
		cuckoo.network.dns_lookup(/http:\/\/someone\.doingevil\.com/)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"($some_string and cuckoo.network.dns_lookup(/http:\/\/someone\.doingevil\.com/))", rule->getCondition()->getText());
	EXPECT_EQ("$some_string", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
DotnetModuleWorks) {
	prepareInput(
R"(
import "dotnet"

rule dotnet_module
{
	condition:
		dotnet.is_dotnet and
		dotnet.version == "v2.0.50727" and
		dotnet.module_name == "axs" and
		dotnet.number_of_streams == 123 and
		dotnet.streams[0].name == "#~" and
		dotnet.streams[0].offset == 123 and
		dotnet.streams[0].size == 123 and
		dotnet.number_of_guids == 123 and
		dotnet.guids[0] == "99c08ffd-f378-a891-10ab-c02fe11be6ef" and
		dotnet.number_of_classes == 123 and
		dotnet.classes[0].fullname == "Launcher.Program" and
		dotnet.classes[0].name == "Launcher.Program" and
		dotnet.classes[0].namespace == "test" and
		dotnet.classes[0].visibility == "private" and
		dotnet.classes[0].type == "class" and
		dotnet.classes[0].abstract and
		dotnet.classes[0].sealed and
		dotnet.classes[0].number_of_generic_parameters == 123 and
		dotnet.classes[0].generic_parameters[0] == "test" and
		dotnet.classes[0].number_of_base_types == 123 and
		dotnet.classes[0].base_types[0] == "test" and
		dotnet.classes[0].number_of_methods == 123 and
		dotnet.classes[0].methods[0].name == "test" and
		dotnet.classes[0].methods[0].visibility == "public" and
		dotnet.classes[0].methods[0].static and
		dotnet.classes[0].methods[0].virtual and
		dotnet.classes[0].methods[0].final and
		dotnet.classes[0].methods[0].abstract and
		dotnet.classes[0].methods[0].return_type == "test" and
		dotnet.classes[0].methods[0].number_of_parameters == 123 and
		dotnet.classes[0].methods[0].parameters[0].name == "test" and
		dotnet.classes[0].methods[0].parameters[0].type == "test" and
		dotnet.classes[0].methods[0].number_of_generic_parameters == 123 and
		dotnet.classes[0].methods[0].generic_parameters[0] == "test" and
		dotnet.number_of_resources == 123 and
		dotnet.resources[0].offset == 0x4d5a and
		dotnet.resources[0].length == 0x4d5a and
		dotnet.resources[0].name == "test" and
		dotnet.assembly.version.major == 7 and
		dotnet.assembly.version.minor == 0 and
		dotnet.assembly.version.build_number == 0 and
		dotnet.assembly.version.revision_number == 0 and
		dotnet.assembly.name == "Keylogger" and
		dotnet.assembly.culture == "test" and
		dotnet.number_of_modulerefs == 123 and
		dotnet.modulerefs[0] == "kernel32" and
		dotnet.typelib == "kernel32" and
		dotnet.assembly_refs[0].version.major == 7 and
		dotnet.assembly_refs[0].version.minor == 0 and
		dotnet.assembly_refs[0].version.build_number == 0 and
		dotnet.assembly_refs[0].version.revision_number == 0 and
		dotnet.assembly_refs[0].name == "test" and
		dotnet.assembly_refs[0].public_key_or_token == "test" and
		dotnet.number_of_user_strings == 123 and
		dotnet.user_strings[0] == "test" and
		dotnet.number_of_field_offsets == 123 and
		dotnet.field_offsets[0] == 8675309
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
    EXPECT_EQ("dotnet.is_dotnet and dotnet.version == \"v2.0.50727\" and dotnet.module_name == \"axs\" and dotnet.number_of_streams == 123 and dotnet.streams[0].name == \"#~\" and dotnet.streams[0].offset == 123 and dotnet.streams[0].size == 123 and dotnet.number_of_guids == 123 and dotnet.guids[0] == \"99c08ffd-f378-a891-10ab-c02fe11be6ef\" and dotnet.number_of_classes == 123 and dotnet.classes[0].fullname == \"Launcher.Program\" and dotnet.classes[0].name == \"Launcher.Program\" and dotnet.classes[0].namespace == \"test\" and dotnet.classes[0].visibility == \"private\" and dotnet.classes[0].type == \"class\" and dotnet.classes[0].abstract and dotnet.classes[0].sealed and dotnet.classes[0].number_of_generic_parameters == 123 and dotnet.classes[0].generic_parameters[0] == \"test\" and dotnet.classes[0].number_of_base_types == 123 and dotnet.classes[0].base_types[0] == \"test\" and dotnet.classes[0].number_of_methods == 123 and dotnet.classes[0].methods[0].name == \"test\" and dotnet.classes[0].methods[0].visibility == \"public\" and dotnet.classes[0].methods[0].static and dotnet.classes[0].methods[0].virtual and dotnet.classes[0].methods[0].final and dotnet.classes[0].methods[0].abstract and dotnet.classes[0].methods[0].return_type == \"test\" and dotnet.classes[0].methods[0].number_of_parameters == 123 and dotnet.classes[0].methods[0].parameters[0].name == \"test\" and dotnet.classes[0].methods[0].parameters[0].type == \"test\" and dotnet.classes[0].methods[0].number_of_generic_parameters == 123 and dotnet.classes[0].methods[0].generic_parameters[0] == \"test\" and dotnet.number_of_resources == 123 and dotnet.resources[0].offset == 0x4d5a and dotnet.resources[0].length == 0x4d5a and dotnet.resources[0].name == \"test\" and dotnet.assembly.version.major == 7 and dotnet.assembly.version.minor == 0 and dotnet.assembly.version.build_number == 0 and dotnet.assembly.version.revision_number == 0 and dotnet.assembly.name == \"Keylogger\" and dotnet.assembly.culture == \"test\" and dotnet.number_of_modulerefs == 123 and dotnet.modulerefs[0] == \"kernel32\" and dotnet.typelib == \"kernel32\" and dotnet.assembly_refs[0].version.major == 7 and dotnet.assembly_refs[0].version.minor == 0 and dotnet.assembly_refs[0].version.build_number == 0 and dotnet.assembly_refs[0].version.revision_number == 0 and dotnet.assembly_refs[0].name == \"test\" and dotnet.assembly_refs[0].public_key_or_token == \"test\" and dotnet.number_of_user_strings == 123 and dotnet.user_strings[0] == \"test\" and dotnet.number_of_field_offsets == 123 and dotnet.field_offsets[0] == 8675309", rule->getCondition()->getText());
	EXPECT_EQ("dotnet", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("8675309", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
DexModuleWorks) {
	prepareInput(
R"(
import "dex"

rule dex_module_has_method_1
{
	condition:
		dex.has_method("<init>")
}

rule dex_module_has_method_2
{
	condition:
		dex.has_method("Lcom/android/tools/ir/server/AppInfo;", "<clinit>")
}

rule dex_module_has_method_3
{
	condition:
		dex.has_method(/init/)
}

rule dex_module_has_method_4
{
	condition:
		dex.has_method(/AppInfo/, /init/)
}

rule dex_module_has_class_1
{
	condition:
		dex.has_class("Lcom/android/tools/ir/server/AppInfo;")
}

rule dex_module_has_class_2
{
	condition:
		dex.has_class(/AppInfo/)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(6u, driver.getParsedFile().getRules().size());

	const auto& rule1 = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("dex.has_method(\"<init>\")", rule1->getCondition()->getText());
	const auto& rule2 = driver.getParsedFile().getRules()[1];
	EXPECT_EQ("dex.has_method(\"Lcom/android/tools/ir/server/AppInfo;\", \"<clinit>\")", rule2->getCondition()->getText());
	const auto& rule3 = driver.getParsedFile().getRules()[2];
	EXPECT_EQ("dex.has_method(/init/)", rule3->getCondition()->getText());
	const auto& rule4 = driver.getParsedFile().getRules()[3];
	EXPECT_EQ("dex.has_method(/AppInfo/, /init/)", rule4->getCondition()->getText());
	const auto& rule5 = driver.getParsedFile().getRules()[4];
	EXPECT_EQ("dex.has_class(\"Lcom/android/tools/ir/server/AppInfo;\")", rule5->getCondition()->getText());
	const auto& rule6 = driver.getParsedFile().getRules()[5];
	EXPECT_EQ("dex.has_class(/AppInfo/)", rule6->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ElfModuleWorks) {
	prepareInput(
R"(
import "elf"

rule elf_module
{
	condition:
		elf.type == elf.ET_EXEC and
		elf.sections[0].type == elf.SHT_NULL
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("elf.type == elf.ET_EXEC and elf.sections[0].type == elf.SHT_NULL", rule->getCondition()->getText());
	EXPECT_EQ("elf", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("SHT_NULL", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HashModuleWorks) {
	prepareInput(
R"(
import "hash"

rule hash_module
{
	condition:
		hash.md5("dummy") == "275876e34cf609db118f3d84b799a790"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(hash.md5("dummy") == "275876e34cf609db118f3d84b799a790")", rule->getCondition()->getText());
	EXPECT_EQ("hash", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("275876e34cf609db118f3d84b799a790", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
MagicModuleWorks) {
	prepareInput(
R"(
import "magic"

rule magic_module
{
	condition:
		magic.type() contains "PDF"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(magic.type() contains "PDF")", rule->getCondition()->getText());
	EXPECT_EQ("magic", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("PDF", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
MathModuleWorks1) {
	prepareInput(
R"(
import "math"

rule math_module
{
	condition:
		math.to_number(math.entropy("dummy") > 7) == 1 and
		math.mode(0, filesize) == 0xFF
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(math.to_number(math.entropy("dummy") > 7) == 1 and math.mode(0, filesize) == 0xFF)", rule->getCondition()->getText());
	EXPECT_EQ("math", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("0xFF", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
MathModuleWorks2) {
	prepareInput(
R"(
import "math"

rule math_module
{
	strings:
		$a = "string A"
		$b = "string B"
	condition:
		math.abs(@a - @b) == 1 and
		math.count(0x4A, filesize - 1024, filesize) >= 10 and
		math.percentage(0xFF, filesize - 1024, filesize) >= 0.9
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(math.abs(@a - @b) == 1 and math.count(0x4A, filesize - 1024, filesize) >= 10 and math.percentage(0xFF, filesize - 1024, filesize) >= 0.9)", rule->getCondition()->getText());
	EXPECT_EQ("math", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("0.9", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
PeModuleWorks1) {
	prepareInput(
R"(
import "pe"

rule pe_module
{
	condition:
		pe.version_info["CompanyName"] == "company"
}
)");

	EXPECT_TRUE(driver.parse(input));

	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	Expression::Ptr condition = rule->getCondition();
	EXPECT_TRUE(condition->isBool());
	auto expEq = std::static_pointer_cast<const EqExpression>(condition);
	EXPECT_EQ(R"(pe.version_info["CompanyName"] == "company")", expEq->getText());
	EXPECT_EQ("pe", expEq->getFirstTokenIt()->getPureText());
	EXPECT_EQ("company", expEq->getLastTokenIt()->getPureText());

	auto expLeft = std::static_pointer_cast<const ArrayAccessExpression>(expEq->getLeftOperand());
	EXPECT_EQ(R"(pe.version_info["CompanyName"])", expLeft->getText());
	EXPECT_EQ("pe", expLeft->getFirstTokenIt()->getPureText());
	EXPECT_EQ("]", expLeft->getLastTokenIt()->getPureText());
	auto expItem = expLeft->getAccessor();
	EXPECT_EQ(R"("CompanyName")", expItem->getText());
	EXPECT_EQ("CompanyName", expItem->getFirstTokenIt()->getPureText());
	EXPECT_EQ("CompanyName", expItem->getLastTokenIt()->getPureText());
	auto arraySymbol = expLeft->getSymbol();
	EXPECT_NE(arraySymbol, nullptr);
	EXPECT_EQ("pe.version_info", arraySymbol->getName());

	auto expArray = std::static_pointer_cast<const StructAccessExpression>(expLeft->getArray());
	EXPECT_EQ("pe.version_info", expArray->getText());
	EXPECT_EQ("pe", expArray->getFirstTokenIt()->getPureText());
	EXPECT_EQ("version_info", expArray->getLastTokenIt()->getPureText());
	auto expPeStructure = expArray->getStructure();
	EXPECT_EQ("pe", expPeStructure->getText());
	EXPECT_EQ("pe", expPeStructure->getFirstTokenIt()->getPureText());
	EXPECT_EQ("pe", expPeStructure->getLastTokenIt()->getPureText());
	auto accessedSymbol = expArray->getSymbol();
	EXPECT_NE(accessedSymbol, nullptr);
	EXPECT_EQ("version_info", accessedSymbol->getName());
	EXPECT_EQ(Symbol::Type::Dictionary, accessedSymbol->getType());
	EXPECT_TRUE(accessedSymbol->isDictionary());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
PeModuleWorks2) {
	prepareInput(
R"(
import "pe"

rule pe_module
{
	condition:
		pe.exports("ExitProcess") or
		pe.version_info["CompanyName"] == "company" and
		pe.characteristics & pe.DLL
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(pe.exports("ExitProcess") or pe.version_info["CompanyName"] == "company" and pe.characteristics & pe.DLL)", rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("DLL", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
PeModuleWorks3) {
	prepareInput(
R"(
import "pe"

rule pe_module
{
	strings:
		$a = { E8 00 00 00 00 }
	condition:
		$a at pe.entry_point_raw and
		pe.rich_signature.version_data == "SomeVersionData"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"($a at pe.entry_point_raw and pe.rich_signature.version_data == "SomeVersionData")", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
VirusTotalSymbolsWork) {
	prepareInput(
R"(
rule virus_total_specific
{
	condition:
		positives > 5 and
		avast == "hero"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(positives > 5 and avast == "hero")", rule->getCondition()->getText());
	EXPECT_EQ("positives", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("hero", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
TransformationToTextWorks) {
	prepareInput(
R"(
import "pe"

/**
 * Random block comment
 */
rule rule_1 : Tag1 Tag2
{
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		pe.exports("ExitProcess")
		and
		for any of them : ( $ at pe.entry_point )
}

import "elf"

// Random one-line comment
rule rule_2
{
	meta:
		valid = true
	strings:
		$abc = "no case full word" nocase fullword
	condition:
		elf.type == elf.ET_EXEC and $abc at elf.entry_point
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(
R"(import "pe"
import "elf"

rule rule_1 : Tag1 Tag2 {
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { AB CD EF }
		$3 = /ab*c/
	condition:
		pe.exports("ExitProcess") and for any of them : ( $ at pe.entry_point )
}

rule rule_2 {
	meta:
		valid = true
	strings:
		$abc = "no case full word" nocase fullword
	condition:
		elf.type == elf.ET_EXEC and $abc at elf.entry_point
})", driver.getParsedFile().getText());

	std::string expected = R"(
import "pe"

/**
 * Random block comment
 */
rule rule_1 : Tag1 Tag2
{
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		pe.exports("ExitProcess") and
		for any of them : ( $ at pe.entry_point )
}

import "elf"

// Random one-line comment
rule rule_2
{
	meta:
		valid = true
	strings:
		$abc = "no case full word" nocase fullword
	condition:
		elf.type == elf.ET_EXEC and
		$abc at elf.entry_point
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RemoveLineBeforeAndWorks) {
	prepareInput(
R"(rule rule_1 {
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		any of them
		or (
		true


		and false)
}

rule rule_2
{
	condition:
		true

		or
		false
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(
R"(rule rule_1 {
	strings:
		$1 = "plain string" wide
		$2 = { AB CD EF }
		$3 = /ab*c/
	condition:
		any of them or (true and false)
}

rule rule_2 {
	condition:
		true or false
})", driver.getParsedFile().getText());

	std::string expected = R"(rule rule_1
{
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		any of them or
		(
			true and
			false
		)
}

rule rule_2
{
	condition:
		true or
		false
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RemoveLineBeforeAndWithCommentsWorks) {
	prepareInput(
R"(rule rule_1 {
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		any of them
		// cuckoo
		or (
		true
		// gvma
		and false)
}

rule rule_2
{
	condition:
		true
		/* cuckoo */

		or false
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(
R"(rule rule_1 {
	strings:
		$1 = "plain string" wide
		$2 = { AB CD EF }
		$3 = /ab*c/
	condition:
		any of them or (true and false)
}

rule rule_2 {
	condition:
		true or false
})", driver.getParsedFile().getText());

	std::string expected = R"(rule rule_1
{
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		any of them or
		// cuckoo
		(
			true and
			// gvma
			false
		)
}

rule rule_2
{
	condition:
		true or
		/* cuckoo */
		false
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RemoveLineBeforeAndWithComments2Works) {
	prepareInput(
R"(
import "cuckoo"

rule rule_1 {
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		any of them // cuckoo
		or (
		true // gvma

		and false)
}

rule rule_2
{
	condition:
		true /* cuckoo */ or false
}

rule rule_3
{
	condition:
		//cuckoo
		cuckoo.sync.mutex(/a/)

		or cuckoo.sync.mutex(/b/)

		//cuckoo 64-bit


		and cuckoo.sync.mutex(/c/)




		or cuckoo.sync.mutex(/d/)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(3u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(
R"(import "cuckoo"

rule rule_1 {
	strings:
		$1 = "plain string" wide
		$2 = { AB CD EF }
		$3 = /ab*c/
	condition:
		any of them or (true and false)
}

rule rule_2 {
	condition:
		true or false
}

rule rule_3 {
	condition:
		cuckoo.sync.mutex(/a/) or cuckoo.sync.mutex(/b/) and cuckoo.sync.mutex(/c/) or cuckoo.sync.mutex(/d/)
})", driver.getParsedFile().getText());

	std::string expected = R"(
import "cuckoo"

rule rule_1
{
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		any of them or // cuckoo
		(
			true and // gvma
			false
		)
}

rule rule_2
{
	condition:
		true /* cuckoo */ or
		false
}

rule rule_3
{
	condition:
		//cuckoo
		cuckoo.sync.mutex(/a/) or
		cuckoo.sync.mutex(/b/) and
		//cuckoo 64-bit
		cuckoo.sync.mutex(/c/) or
		cuckoo.sync.mutex(/d/)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
MultipleRulesWorks2) {
	prepareInput(
R"(
rule rule_1
{
	condition:
		for any of them : ( $ at entrypoint )
}

rule rule2
{
	meta:
		valid = "ahoj"
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(
R"(rule rule_1 {
	condition:
		for any of them : ( $ at entrypoint )
}

rule rule2 {
	meta:
		valid = "ahoj"
	condition:
		true
})", driver.getParsedFile().getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
KbMbIntegerMultipliersWorks) {
	prepareInput(
R"(
rule kb_mb_integer_multipliers
{
	condition:
		(1KB <= filesize) and
		(filesize <= 1MB)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(1KB <= filesize) and (filesize <= 1MB)", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ReferencingRuleFromOtherRuleWorks) {
	prepareInput(
R"(
rule rule_1
{
	condition:
		filesize > 100KB
}

rule rule_2
{
	condition:
		rule_1 and
		(filesize < 10MB)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

	const auto& rule1 = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("filesize > 100KB", rule1->getCondition()->getText());

	const auto& rule2 = driver.getParsedFile().getRules()[1];
	EXPECT_EQ("rule_1 and (filesize < 10MB)", rule2->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpWithSuffixModifierWorks) {
	prepareInput(
R"(
import "cuckoo"

rule regexp_with_suffix_modifier
{
	strings:
		$some_string = { 01 02 03 04 05 05 }
	condition:
		$some_string and
		cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/is)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"($some_string and cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/is))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
GlobalVariablesWorks) {
	prepareInput(
R"(rule rule_with_global_variables
{
	condition:
		new_file and
		positives > 10 and
		signatures matches /Trojan\.Generic.*/ and
		file_type contains "pe"
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(new_file and positives > 10 and signatures matches /Trojan\.Generic.*/ and file_type contains "pe")", rule->getCondition()->getText());
	EXPECT_EQ("new_file", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("pe", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
LengthOfHexStringWorks) {
	prepareInput(
R"(rule rule_with_some_hex_string
{
	strings:
		$hex_string = { 11 ?? 22 [4-5] ( 66 | 77 ) 88 }
	condition:
		$hex_string
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto string = strings[0];
	ASSERT_TRUE(string->isHex());

	EXPECT_EQ(12u, static_cast<const HexString*>(string)->getLength());

	EXPECT_EQ("$hex_string", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("$hex_string", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexStringWithSpacesInJumpWorks) {
	prepareInput(
R"(rule rule_with_some_hex_string {
	strings:
		$hex = { A1 [8 - 123] A2 }
	condition:
		$hex
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto string = strings[0];
	ASSERT_TRUE(string->isHex());

	EXPECT_EQ("$hex", string->getIdentifier());
	EXPECT_EQ("{ A1 [8-123] A2 }", string->getText());

	std::string expected =
R"(rule rule_with_some_hex_string
{
	strings:
		$hex = { A1 [8-123] A2 }
	condition:
		$hex
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ComplicatedHexStringAlterationWorks) {
	prepareInput(
R"(rule rule_with_complicated_alteration_hex_string
{
	strings:
		$hex_string = { 11 ( 12 | 22 | 33 | ( 44 | ( 55 | ?? ) | 66 ) | 77 | 88 ) }
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_complicated_alteration_hex_string", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$hex_string", hexString->getIdentifier());
	EXPECT_EQ("{ 11 ( 12 | 22 | 33 | ( 44 | ( 55 | ?? ) | 66 ) | 77 | 88 ) }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ComplicatedHexStringWorks) {
	prepareInput(
R"(rule rule_with_complicated_hex_string
{
	strings:
		$hex_string = { ( 11 1? | 22 ?0 19 49 | 33 30 | ( 44 | ( 55 | ?? ) | 66 ) | 77 | 88 ) }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_complicated_hex_string", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$hex_string", hexString->getIdentifier());
	EXPECT_EQ("{ ( 11 1? | 22 ?0 19 49 | 33 30 | ( 44 | ( 55 | ?? ) | 66 ) | 77 | 88 ) }", hexString->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}


TEST_F(ParserTests,
NibbleGetterWorks) {
	prepareInput(
R"(rule rule_with_some_hex_string
{
	strings:
		$hex_string = { 9F }
	condition:
		$hex_string
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto string = strings[0];
	ASSERT_TRUE(string->isHex());

	const auto units = static_cast<const HexString*>(string)->getUnits();
	EXPECT_EQ(0x9, std::static_pointer_cast<HexStringNibble>(units[0])->getValue());
	EXPECT_EQ(0xF, std::static_pointer_cast<HexStringNibble>(units[1])->getValue());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
HexEscapeWorks) {
	prepareInput(
R"(
import "pe"

rule rule_with_hex_escaped_works
{
	meta:
		simple_string_meta = "Simple is \x11"
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto simple_meta = rule->getMetaWithName("simple_string_meta");
	EXPECT_EQ(R"("Simple is \x11")", simple_meta->getValue().getText());
	EXPECT_EQ("Simple is \x11", simple_meta->getValue().getPureText());
	EXPECT_EQ(R"(simple_string_meta = "Simple is \x11")", simple_meta->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
EscapedSequencesInMetaWorks) {
	prepareInput(
R"(
import "pe"

rule rule_with_escaped_meta_works
{
	meta:
		str_meta_0 = "Here are a@t"
		str_meta_1 = "Here are a\x40t"
		str_meta_2 = "Here are \\,\x0A"
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strMeta0 = rule->getMetaWithName("str_meta_0");
	auto strMeta1 = rule->getMetaWithName("str_meta_1");
	auto strMeta2 = rule->getMetaWithName("str_meta_2");

	ASSERT_NE(strMeta0, nullptr);
	EXPECT_EQ("\"Here are a@t\"", strMeta0->getValue().getText());
	EXPECT_EQ( R"(Here are a@t)", strMeta0->getValue().getPureText());

	ASSERT_NE(strMeta1, nullptr);
	EXPECT_EQ(R"("Here are a\x40t")", strMeta1->getValue().getText());
	EXPECT_EQ( R"(Here are a@t)", strMeta1->getValue().getPureText());
	EXPECT_EQ(   "Here are a@t", strMeta1->getValue().getPureText());

	ASSERT_NE(strMeta2, nullptr);
	EXPECT_EQ(R"("Here are \\,\x0A")", strMeta2->getValue().getText());
	EXPECT_EQ( R"(Here are \,
)", strMeta2->getValue().getPureText());
	EXPECT_EQ(   "Here are \\,\x0A", strMeta2->getValue().getPureText());

	EXPECT_EQ("true", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
EscapedSequencesWorks) {
	prepareInput(
R"(
import "pe"

rule rule_with_escaped_double_quotes_works
{
	meta:
		str_meta = "Here are \t\r\n\\\x01\xff"
	strings:
		$str = "Another \t\r\n\\\x01\xff"
	condition:
		pe.rich_signature.clear_data == "DanS\t\r\n\\\x01\xff"
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strMeta = rule->getMetaWithName("str_meta");
	ASSERT_NE(strMeta, nullptr);


	EXPECT_EQ(R"("Here are \t\r\n\\\x01\xff")", strMeta->getValue().getText());
	EXPECT_EQ("Here are \t\r\n\\\x01""\xff", strMeta->getValue().getPureText());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto str = strings[0];
	ASSERT_TRUE(str->isPlain());

	EXPECT_EQ(R"("Another \t\r\n\\\x01\xff")", str->getText());
	EXPECT_EQ("Another \t\r\n\\\x01\xff", str->getPureText());

	std::string expected = R"(pe.rich_signature.clear_data == "DanS\t\r\n\\\x01\xff")";
	EXPECT_EQ(expected, rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("DanS\t\r\n\\\x01\xff", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
InvalidEscapedSequence1) {
	prepareInput(
R"(rule rule_with_invalid_escape_sequence {
	strings:
		$str = "\t\l"
	condition:
		$str
}"
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 3.13-14: Syntax error: Unknown escaped sequence '\\l'", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
InvalidEscapedSequence2) {
	prepareInput(
R"(rule rule_with_invalid_escape_sequence {
	strings:
		$st1 = "\n\n\n"
		$st2 = "\t\l"
	condition:
		$st1 or $st2
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.13-14: Syntax error: Unknown escaped sequence '\\l'", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
NewlineInHexString) {
	prepareInput(
R"(rule rule_with_hex_string_with_newlines
{
	strings:
		$str = {
			AA
			BB
			[5-6]
			CC
		}
	condition:
		$str
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto string = strings[0];
	ASSERT_TRUE(string->isHex());

	EXPECT_EQ("{ AA BB [5-6] CC }", string->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ErrorWhenUnknownTokenAfterImport) {
	prepareInput(
R"(import "pe";

rule public_rule {
	condition:
		true
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 1.8-11: Syntax error: Unknown symbol on input, expected one of @end, global, private, rule, import, include", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
PeDataDirectoryIsArray) {
	prepareInput(
R"(import "pe"

rule public_rule
{
	condition:
		pe.data_directories[0].virtual_address == 0 and
		pe.data_directories[0].size == 0
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ("pe.data_directories[0].virtual_address == 0 and pe.data_directories[0].size == 0", rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("0", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AnonymousStrings) {
	prepareInput(
R"(rule public_rule
{
	strings:
		$ = "Hello World"
		$ = "Bye World"
	condition:
		all of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(2u, strings.size());

	EXPECT_EQ("$", strings[0]->getIdentifier());
	EXPECT_EQ("Hello World", strings[0]->getPureText());
	EXPECT_EQ("$", strings[1]->getIdentifier());
	EXPECT_EQ("Bye World", strings[1]->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AllOfThemInOperator) {
	prepareInput(
R"(rule public_rule_with_in_operator
{
	strings:
		$s1 = "Hello World"
		$s2 = "Bye World"
	condition:
		all of them in (0 .. filesize)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
	EXPECT_EQ("all", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());
}

TEST_F(ParserTests,
AllOfInOperatorAndAnyOfInOperator) {
	prepareInput(
R"(rule public_rule_with_in_operator
{
	strings:
		$a1 = "Hello World"
		$a2 = "Bye World"
		$b1 = "Another"
	condition:
		all of ($a*) in (filesize - 500 .. filesize) and
		any of ($a*, $b*) in (1000 .. 2000)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
	EXPECT_EQ("all", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());
}

TEST_F(ParserTests,
StringCountInRange) {
	prepareInput(
R"(rule public_rule_with_in_operator
{
	strings:
		$a = "foo"
	condition:
		#a in (filesize - 500 .. filesize) == 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
	EXPECT_EQ("#a in (filesize - 500 .. filesize) == 2", rule->getCondition()->getText());
	EXPECT_EQ("#a", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("2", rule->getCondition()->getLastTokenIt()->getPureText());
}

TEST_F(ParserTests,
CommentsInCommonLocations) {
	prepareInput(
R"(
// We need pe for exports
import "pe"

/**
 * Random block comment
 */
rule rule_1 : Tag1 Tag2 {
	// Random comment meta
	meta:
		// Random comment meta info
		info = "meta info"
		version = 2
		// Random comment meta version
	// Random comment strings
	strings:
		// Random comment strings 1
		$1 = "plain string" wide //xor
		$2 = { ab cd ef }
		// Random comment strings 3
		$3 = /ab*c/
	// Random comment condition
	condition:
		// Random comment expression
		pe.exports("ExitProcess") and for any of them : ( $ at pe.entry_point )
}

/* SHORT BLOCK COMMENT */
import "elf"

// Random one-line comment
rule rule_2 {
	/*
	 meta comment*/
	meta:
		valid = true
	/*
	 strings comment
	*/
	strings: // COMMENT
		$abc = "no case full word" nocase fullword // xor
	/*
		condition comment
	*/
	condition:
		elf.type == elf.ET_EXEC
		and
		$abc at elf.entry_point
}
// Comment at the end of file
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(
R"(import "pe"
import "elf"

rule rule_1 : Tag1 Tag2 {
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { AB CD EF }
		$3 = /ab*c/
	condition:
		pe.exports("ExitProcess") and for any of them : ( $ at pe.entry_point )
}

rule rule_2 {
	meta:
		valid = true
	strings:
		$abc = "no case full word" nocase fullword
	condition:
		elf.type == elf.ET_EXEC and $abc at elf.entry_point
})", driver.getParsedFile().getText());

	std::string expected = R"(
// We need pe for exports
import "pe"

/**
 * Random block comment
 */
rule rule_1 : Tag1 Tag2
{
	// Random comment meta
	meta:
		// Random comment meta info
		info = "meta info"
		version = 2
		// Random comment meta version
	// Random comment strings
	strings:
		// Random comment strings 1
		$1 = "plain string" wide //xor
		$2 = { ab cd ef }
		// Random comment strings 3
		$3 = /ab*c/
	// Random comment condition
	condition:
		// Random comment expression
		pe.exports("ExitProcess") and
		for any of them : ( $ at pe.entry_point )
}

/* SHORT BLOCK COMMENT */
import "elf"

// Random one-line comment
rule rule_2
{
	/*
	 meta comment*/
	meta:
		valid = true
	/*
	 strings comment
	*/
	strings:                                           // COMMENT
		$abc = "no case full word" nocase fullword // xor
	/*
		condition comment
	*/
	condition:
		elf.type == elf.ET_EXEC and
		$abc at elf.entry_point
}
// Comment at the end of file
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
	EXPECT_EQ(2u, driver.getParsedFile().getRules().size());
	const auto& rule2 = driver.getParsedFile().getRules()[1];
	EXPECT_EQ("elf", rule2->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("entry_point", rule2->getCondition()->getLastTokenIt()->getPureText());
}

TEST_F(ParserTests,
CommentsInHexString) {
	prepareInput(
R"(
rule rule_name {
	strings:
		$1 = { AB CD /* comment 1 */ 01 }
		$2 = { AB CD /* comment 2 */ }
		$3 = { ( 01 | // COMMENT
			02 ) }
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(
R"(rule rule_name {
	strings:
		$1 = { AB CD 01 }
		$2 = { AB CD }
		$3 = { ( 01 | 02 ) }
	condition:
		true
})", driver.getParsedFile().getText());
	std::string expected = R"(
rule rule_name
{
	strings:
		$1 = { AB CD /* comment 1 */ 01 }
		$2 = { AB CD /* comment 2 */ }
		$3 = {
			( 01 | // COMMENT
			02 )
		}
	condition:
		true
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
CommentsInCondition) {
	prepareInput(
R"(
import "pe"

rule rule_1 : Tag1 Tag2
{
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		/*not $1 and*/ pe.exports("ExitProcess") and for any of them : ( $ at pe.entry_point )
}

import "elf"

rule rule_2
{
	meta:
		valid = true
	strings:
		$1 = "no case full word" nocase fullword
		$2 = "String 2"
		$3 = /./
		$5 = "String 5"
	condition:
		elf.type == elf.ET_EXEC
		and 2 of ($1, $2, $3 /*, $4*/, $5)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());
	const auto& rule1 = driver.getParsedFile().getRules()[0];
	const auto& rule2 = driver.getParsedFile().getRules()[1];
	EXPECT_EQ("pe", rule1->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule1->getCondition()->getLastTokenIt()->getPureText());
	EXPECT_EQ("elf", rule2->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule2->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(
R"(import "pe"
import "elf"

rule rule_1 : Tag1 Tag2 {
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { AB CD EF }
		$3 = /ab*c/
	condition:
		pe.exports("ExitProcess") and for any of them : ( $ at pe.entry_point )
}

rule rule_2 {
	meta:
		valid = true
	strings:
		$1 = "no case full word" nocase fullword
		$2 = "String 2"
		$3 = /./
		$5 = "String 5"
	condition:
		elf.type == elf.ET_EXEC and 2 of ($1, $2, $3, $5)
})", driver.getParsedFile().getText());

	std::string expected = R"(
import "pe"

rule rule_1 : Tag1 Tag2
{
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		/*not $1 and*/ pe.exports("ExitProcess") and
		for any of them : ( $ at pe.entry_point )
}

import "elf"

rule rule_2
{
	meta:
		valid = true
	strings:
		$1 = "no case full word" nocase fullword
		$2 = "String 2"
		$3 = /./
		$5 = "String 5"
	condition:
		elf.type == elf.ET_EXEC and
		2 of ($1, $2, $3 /*, $4*/, $5)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForCycleMultipleRows)
{
	prepareInput(
R"(
import "pe"

private rule RULE_1
{
	meta:
		author = "Mr. Avastian"
		description = "cool rule"
		reliability = "test"
		strain = "strain"
		type = "type"
		severity = "severity"
		rule_type = "type"
		hash = "9b7eb04d21397a5afb6b96985196453c9af6011578b1a7f8c7dd464875e6b98b"
		hash = "8399656db73fe734d110e11b01632b1bebb7a7d6fedbefdae1607847092f8628"
		hash = "517b882a9365026168f72fa88ace14f1976e027e37e5fc27f2a298a6730bb3a7"
		hash = "fcc2afe8eca464971d96867e7898b4c929cde65e4dab126a3ae48aee48083256"
	strings:
		// Comments are super fun!
		$h0 = { A1 00 01 00 00 01 E1 10 } ///< Freedom . for . comments!
		$h1 = { B2 00 01 00 00 66 E2 02 }
		$h2 = { C3 01 00 00 01 5a E1 30 }

		$h3 = { D4 00 00 01 00 5b E2 45 }
		$h4 = { E5 00 00 00 00 5e E1 66 }
		$h5 = { F6 00 01 00 01 5f E2 11 }
	condition:
		for any of ($h*) : (
			# < 20 and
			for any i in (1 .. #) : ( //Comment inside expression
				uint32be(1) == 5 and // comment right after and
				filesize >= 10 and
				all of them and
				entrypoint and
				@h1 < pe.overlay.offset
			)
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(6u, strings.size());

	EXPECT_EQ("$h0", strings[0]->getIdentifier());

	std::string expected = R"(
import "pe"

private rule RULE_1
{
	meta:
		author = "Mr. Avastian"
		description = "cool rule"
		reliability = "test"
		strain = "strain"
		type = "type"
		severity = "severity"
		rule_type = "type"
		hash = "9b7eb04d21397a5afb6b96985196453c9af6011578b1a7f8c7dd464875e6b98b"
		hash = "8399656db73fe734d110e11b01632b1bebb7a7d6fedbefdae1607847092f8628"
		hash = "517b882a9365026168f72fa88ace14f1976e027e37e5fc27f2a298a6730bb3a7"
		hash = "fcc2afe8eca464971d96867e7898b4c929cde65e4dab126a3ae48aee48083256"
	strings:
		// Comments are super fun!
		$h0 = { A1 00 01 00 00 01 E1 10 } ///< Freedom . for . comments!
		$h1 = { B2 00 01 00 00 66 E2 02 }
		$h2 = { C3 01 00 00 01 5a E1 30 }

		$h3 = { D4 00 00 01 00 5b E2 45 }
		$h4 = { E5 00 00 00 00 5e E1 66 }
		$h5 = { F6 00 01 00 01 5f E2 11 }
	condition:
		for any of ($h*) : (
			# < 20 and
			for any i in (1 .. #) : (    //Comment inside expression
				uint32be(1) == 5 and // comment right after and
				filesize >= 10 and
				all of them and
				entrypoint and
				@h1 < pe.overlay.offset
			)
		)
}
)";
	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ForCycleMultipleRowsWithCRLF)
{
	prepareInput("\r\nimport \"pe\"\r\n\r\nprivate rule RULE_1\r\n{\r\n\tmeta:\r\n\t\tauthor = \"Mr. Avastian\"\r\n\t\tdescription = \"cool rule\"\r\n\thash = \"hash2\"\r\n\t\thash = \"hash1\"\r\n\tstrings:\r\n\t\t$h0 = \"str0\"\r\n\t\t$h1 = \"str1\"\r\n\tcondition:\r\nfor any of ($h*) : (\r\n\t\t\t# < 20 and\r\n\tfor any i in (1 .. #) : (    //Comment inside expression\r\n\t\tuint32be(1) == 5 and // comment right after and\r\n\t\t\t\tfilesize >= 10 and\r\n\t\t\t\tall of them and\r\n\t\t\t\tentrypoint and\r\n\t\t\t\t@h1 < pe.overlay.offset\r\n\t\t\t)\r\n\t\t)\r\n}\r\n");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(2u, strings.size());

	EXPECT_EQ("$h0", strings[0]->getIdentifier());

	EXPECT_EQ("for", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	std::string expected = "\r\nimport \"pe\"\r\n\r\nprivate rule RULE_1\r\n{\r\n\tmeta:\r\n\t\tauthor = \"Mr. Avastian\"\r\n\t\tdescription = \"cool rule\"\r\n\t\thash = \"hash2\"\r\n\t\thash = \"hash1\"\r\n\tstrings:\r\n\t\t$h0 = \"str0\"\r\n\t\t$h1 = \"str1\"\r\n\tcondition:\r\n\t\tfor any of ($h*) : (\r\n\t\t\t# < 20 and\r\n\t\t\tfor any i in (1 .. #) : (    //Comment inside expression\r\n\t\t\t\tuint32be(1) == 5 and // comment right after and\r\n\t\t\t\tfilesize >= 10 and\r\n\t\t\t\tall of them and\r\n\t\t\t\tentrypoint and\r\n\t\t\t\t@h1 < pe.overlay.offset\r\n\t\t\t)\r\n\t\t)\r\n}\r\n";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
OneMoreTest) {
	prepareInput(
R"(rule public_rule
{
	strings:
		$1 = "Hello World"
		$2 = "Bye World"
	condition:
		true and
		uint32be(1) and
		filesize > 0xFF
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(2u, strings.size());

	EXPECT_EQ("$1", strings[0]->getIdentifier());
	EXPECT_EQ("Hello World", strings[0]->getPureText());
	EXPECT_EQ("$2", strings[1]->getIdentifier());
	EXPECT_EQ("Bye World", strings[1]->getPureText());
	EXPECT_EQ("true and uint32be(1) and filesize > 0xFF", rule->getCondition()->getText());
	EXPECT_EQ("true", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("0xFF", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
NonUTFmetaWorks) {
	prepareInput(
R"(
import "cuckoo"

rule nonutf_meta
{
	meta:
		author = "내"
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_TRUE(rule->getMetas()[0].getValue().isString());
	EXPECT_EQ(R"(내)", rule->getMetas()[0].getValue().getPureText());
	EXPECT_EQ(R"("내")", rule->getMetas()[0].getValue().getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
NonUTFconditionWorks) {
	prepareInput(
R"(
import "cuckoo"

rule nonutf_condition
{
	condition:
		cuckoo.filesystem.file_access(/내/)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(cuckoo.filesystem.file_access(/내/))", rule->getCondition()->getText());

	std::string expected =
R"(
import "cuckoo"

rule nonutf_condition
{
	condition:
		cuckoo.filesystem.file_access(/내/)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
NonUTFcommentWorks) {
	prepareInput(
R"(
import "cuckoo"

rule nonutf_condition
{
	/*\x83*/
	strings:
		$s1 = "text" // \x83\xe9
	condition:
		true
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule nonutf_condition
{
	/*\x83*/
	strings:
		$s1 = "text" // \x83\xe9
	condition:
		true
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
NonUTFcommentsWork) {
	prepareInput(
R"(
import "cuckoo"

rule nonutf_condition
{
	/*  */
	/* /내/ */
	strings:
		$s1 = "a"    // /내/
		$s2 = "b" // pe.rich_signature == "Pop\x83\xe9"
		$s3 = "c"    // // pe.rich_signature == "Pop\x83\xe9"
	condition:
		false or // /내/
		false or // pe.rich_signature == "Pop\x00\x83\x00\xe9POP"
		true // // pe.rich_signature == "Pop\x00\x83\x00\xe9POP"
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule nonutf_condition
{
	/*  */
	/* /내/ */
	strings:
		$s1 = "a" // /내/
		$s2 = "b" // pe.rich_signature == "Pop\x83\xe9"
		$s3 = "c" // // pe.rich_signature == "Pop\x83\xe9"
	condition:
		false or // /내/
		false or // pe.rich_signature == "Pop\x00\x83\x00\xe9POP"
		true     // // pe.rich_signature == "Pop\x00\x83\x00\xe9POP"
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RemoveTrailingWhitespacesFromComments) {
	prepareInput(
R"(
rule trailing_whitespaces_in_comments_rule
{
	meta:
		author = "Mr. Avastien" // comment with extra tab	
	strings:
		$s1 = "text" // comment with extra space 
	condition:
		$s1
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
rule trailing_whitespaces_in_comments_rule
{
	meta:
		author = "Mr. Avastien" // comment with extra tab
	strings:
		$s1 = "text" // comment with extra space
	condition:
		$s1
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AddMetaAfterParse) {
	prepareInput(
R"(
rule rule_1
{
	condition:
		true
}


rule rule_2
{
	strings:
		$s0 = "string 0"
	condition:
		$s0
}


rule rule_3
{
	meta:
		author = "Mr. Avastian"
	condition:
		false
}
)");

	EXPECT_TRUE(driver.parse(input));
	const auto& rules = driver.getParsedFile().getRules();
	EXPECT_EQ(rules.size(), 3);

	auto rule = rules[0];
	ASSERT_EQ(0u, rule->getMetas().size());
	uint64_t u = 42;
	rule->addMeta("new_int_meta", Literal(u));
	ASSERT_EQ(1u, rule->getMetas().size());
	EXPECT_TRUE(rule->getMetas()[0].getValue().isInt());
	EXPECT_EQ(42, rule->getMetas()[0].getValue().getInt());
	EXPECT_EQ(R"(42)", rule->getMetas()[0].getValue().getText());

	rule = rules[1];
	ASSERT_EQ(0u, rule->getMetas().size());
	rule->addMeta("new_string_meta", Literal("string value"));
	ASSERT_EQ(1u, rule->getMetas().size());
	EXPECT_TRUE(rule->getMetas()[0].getValue().isString());
	EXPECT_EQ(R"("string value")", rule->getMetas()[0].getValue().getText());

	rule = rules[2];
	ASSERT_EQ(1u, rule->getMetas().size());
	rule->addMeta("new_bool_meta", Literal(true));
	ASSERT_EQ(2u, rule->getMetas().size());
	const Meta* meta = rule->getMetaWithName("new_bool_meta");
	ASSERT_NE(meta, nullptr);
	EXPECT_EQ(meta->getKey(), "new_bool_meta");
	EXPECT_TRUE(meta->getValue().isBool());
	EXPECT_TRUE(meta->getValue().getBool());
	EXPECT_EQ(meta->getValue().getText(), "true");

std::string expected = R"(
rule rule_1
{
	meta:
		new_int_meta = 42
	condition:
		true
}


rule rule_2
{
	meta:
		new_string_meta = "string value"
	strings:
		$s0 = "string 0"
	condition:
		$s0
}


rule rule_3
{
	meta:
		author = "Mr. Avastian"
		new_bool_meta = true
	condition:
		false
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
SetTagsAfterParse) {
	prepareInput(
R"(
rule rule_1 {
	condition:
		true
}

rule rule_2
{
	condition:
		true
}

rule rule_3 : TagA {
	strings:
		$s0 = "string 0"
	condition:
		$s0
}
)");

	EXPECT_TRUE(driver.parse(input));
	const auto& rules = driver.getParsedFile().getRules();
	EXPECT_EQ(rules.size(), 3);

	auto rule = rules[0];
	std::vector<std::string> tags = {"Tag1", "Tag2"};
	rule->setTags(tags);

	rule = rules[1];
	rule->setTags(tags);

	rule = rules[2];
	tags = {"TagB", "TagC"};
	rule->setTags(tags);

	EXPECT_EQ("$s0", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("$s0", rule->getCondition()->getLastTokenIt()->getPureText());

	std::string expected = R"(
rule rule_1 : Tag1 Tag2
{
	condition:
		true
}

rule rule_2 : Tag1 Tag2
{
	condition:
		true
}

rule rule_3 : TagB TagC
{
	strings:
		$s0 = "string 0"
	condition:
		$s0
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RemoveMetasAfterParse) {
	prepareInput(
R"(
rule rule_1
{
	meta:
		bool_meta = true
		int_meta = 42
	condition:
		true
}

rule rule_2
{
	meta:
		author = "Mr. Avastian"
	strings:
		$s0 = "string 0"
	condition:
		$s0
}

rule rule_3
{
	meta:
		hash = "123"
		hash = "456"
		hash = "789"
	condition:
		false
}
)");

	EXPECT_TRUE(driver.parse(input));
	const auto& rules = driver.getParsedFile().getRules();
	EXPECT_EQ(rules.size(), 3);

	auto rule = rules[0];
	rule->removeMetas("int_meta");

	rule = rules[1];
	rule->removeMetas("author");

	rule = rules[2];
	rule->removeMetas("hash");

std::string expected = R"(
rule rule_1
{
	meta:
		bool_meta = true
	condition:
		true
}

rule rule_2
{
	strings:
		$s0 = "string 0"
	condition:
		$s0
}

rule rule_3
{
	condition:
		false
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownImport) {
	prepareInput(
R"(
import "dummy"

rule abc
{
	condition:
		true
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteReferenceUnknownSymbol) {
	prepareInput(
R"(
rule abc
{
	condition:
		unknown_symbol
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownObjectSymbol) {
	prepareInput(
R"(rule abc
{
	condition:
		unknown_object.some_element
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownObjectSymbolFromKnownModule) {
	prepareInput(
R"(import "cuckoo"

rule abc
{
	condition:
		cuckoo.unknown_object.some_element
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownArraySymbol) {
	prepareInput(
R"(import "pe"

rule abc
{
	condition:
		unknown_array_one[0]
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownArraySymbolFromKnownModule) {
	prepareInput(
R"(import "pe"

rule abc
{
	condition:
		pe.unknown_array_two[10]
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownArraySymbolFromUnknownModule) {
	prepareInput(
R"(import "dummy"

rule abc
{
	condition:
		dummy.unknown_array[10]
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownObjectSymbolFromUnknownModule) {
	prepareInput(
R"(import "dummy"

rule abc
{
	condition:
		dummy.unknown_object.some_element
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownForDict) {
	prepareInput(
R"(rule abc
{
	condition:
		for all k, v in unknown : (  k == "foo" and v == "bar" )
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(rule abc
{
	condition:
		for all k, v in unknown : (
			k == "foo" and
			v == "bar"
		)
}
)";
	ASSERT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownForDictFromKnownModule) {
	prepareInput(
R"(import "cuckoo"

rule abc
{
	condition:
		for all k, v in cuckoo.unknown : (  k == "foo" and v == "bar" )
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(import "cuckoo"

rule abc
{
	condition:
		for all k, v in cuckoo.unknown : (
			k == "foo" and
			v == "bar"
		)
}
)";
	ASSERT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownForDictFromUnknownModule) {
	prepareInput(
R"(import "dummy"

rule abc
{
	condition:
		for all k, v in dummy.unknown : (  k == "foo" and v == "bar" )
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(import "dummy"

rule abc
{
	condition:
		for all k, v in dummy.unknown : (
			k == "foo" and
			v == "bar"
		)
}
)";
	ASSERT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownFor) {
	prepareInput(
R"(rule abc
{
	condition:
		for all i in unknown : ( i == "foo" )
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownForFromKnownModule) {
	prepareInput(
R"(import "cuckoo"

rule abc
{
	condition:
		for all i in cuckoo.unknown : ( i == "foo" )
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownForFromUnknownModule) {
	prepareInput(
R"(rule abc
{
	condition:
		for all i in unknown : ( i == "foo" )
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownFunctionCall) {
	prepareInput(
R"(rule abc
{
	condition:
		unknown("param")
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownFunctionCallFromKnownModule) {
	prepareInput(
R"(import "cuckoo"

rule abc
{
	condition:
		cuckoo.unknown("param")
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownFunctionCallFromUnknownModule) {
	prepareInput(
R"(import "dummy"

rule abc
{
	condition:
		dummy.unknown("param")
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteUnknownFunctionOverloadOfKnownFunction) {
	prepareInput(
R"(import "cuckoo"

rule abc
{
	condition:
		cuckoo.network.http_request(42)
}
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseIncompleteRuleNotFinished) {
	prepareInput(
R"(
rule abc
{
	condition:
)"
);
	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(0u, driver.getParsedFile().getRules().size());
	std::vector<std::string> expected{"\n", "rule", "abc", "\n", "{", "\n", "condition", ":", "\n" };
	ASSERT_EQ(expected, driver.getParsedFile().getTokenStream()->getTokensAsText());
}

TEST_F(ParserTests,
AutoformattingClosingBracket) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule {
	condition:
		for 2 i in (1..4) : (
			i == 4 and (
				true or
				false
				)
		)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		for 2 i in (1 .. 4) : (
			i == 4 and
			(
				true or
				false
			)
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingClosingDoubleBracket) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule {
	condition:
		for 2 i in (1 .. 4) : (
			i == 4 and ((
				true or
				false
				))
		)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		for 2 i in (1 .. 4) : (
			i == 4 and
			((
				true or
				false
			))
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingClosingBracketWithOtherBracketsInside) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule {
	condition:
		for 2 i in (1 .. 4) : (
			i == 4 and (((
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?brokolice\.cz/) or
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?kvetak\.cz/)
				)))
		)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		for 2 i in (1 .. 4) : (
			i == 4 and
			(((
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?brokolice\.cz/) or
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?kvetak\.cz/)
			)))
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingMultipleLineBrackets) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule {
	condition:
		for 2 i in (1 .. 4) : (
			(i == 1) or
			(i == 2) or
			(i == 3) or
			(
				i == 4 and
				(
					cuckoo.network.http_request(/http(s)?:\/\/(www\.)?brokolice\.cz/) or
					cuckoo.network.http_request(/http(s)?:\/\/(www\.)?kvetak\.cz/)
				)
			)
		)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		for 2 i in (1 .. 4) : (
			(i == 1) or
			(i == 2) or
			(i == 3) or
			(
				i == 4 and
				(
					cuckoo.network.http_request(/http(s)?:\/\/(www\.)?brokolice\.cz/) or
					cuckoo.network.http_request(/http(s)?:\/\/(www\.)?kvetak\.cz/)
				)
			)
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingProperAlignment) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule {
	condition:
		false or (
			true and (false or (true and (
						true
						) /*comment*/))
						)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("false", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		false or
		(
			true and
			(
				false or
				(
					true and
					(
						true
					) /*comment*/
				)
			)
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingProperAlignmentOrStatement) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule
{
	condition:
		not false and
		not false and
		false or (
			true and (
				(	false or
					false or
					false) or (true
				)
			)
		)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		not false and
		not false and
		false or
		(
			true and
			(
				(
					false or
					false or
					false
				) or
				(
					true
				)
			)
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingAddNewlinesMinimal) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule
{
	condition:
			( /* comment */ false and true )
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		(
			/* comment */ false and
			true
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingAddNewLines) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule {
	condition:
		false or (
			true and (
				false or (
					true and (
						true
					)))
					)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		false or
		(
			true and
			(
				false or
				(
					true and
					(
						true
					)
				)
			)
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingAddNewlinesToBothSides) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule {
	condition:
		false or
		(true and
			(
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?brokolice\.cz/) or
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?kvetak\.cz/)
				))
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{
	condition:
		false or
		(
			true and
			(
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?brokolice\.cz/) or
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?kvetak\.cz/)
			)
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingAddCRLF) {
	prepareInput(
"import \"cuckoo\"\r\n\r\nrule public_rule {\r\n	condition:\r\n		false or\r\n		(true and\r\n			(\r\n				true or\r\n				false\r\n				))\r\n}");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
"import \"cuckoo\"\r\n\r\nrule public_rule\r\n{\r\n	condition:\r\n		false or\r\n		(\r\n			true and\r\n			(\r\n				true or\r\n				false\r\n			)\r\n		)\r\n}\r\n";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingNoSpaceBeforeArrayAccess) {
	prepareInput(
R"(
import "cuckoo"
import "pe"

rule public_rule {
	condition:
		pe.version_info["ProductName"] == "Test product name"
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"
import "pe"

rule public_rule
{
	condition:
		pe.version_info["ProductName"] == "Test product name"
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingSpaceBeforeComments) {
	prepareInput(
R"(
import "cuckoo"

rule public_rule { //comment 0
	condition:
		false or
		(//comment 1
			true and
			(/*comment 2*/
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?brokolice\.cz/) or
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?kvetak\.cz/)
			)//comment 3
		)/*comment 4*/
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("false", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule->getCondition()->getLastTokenIt()->getPureText());

	std::string expected =
R"(
import "cuckoo"

rule public_rule
{ //comment 0
	condition:
		false or
		( //comment 1
			true and
			(
				/*comment 2*/
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?brokolice\.cz/) or
				cuckoo.network.http_request(/http(s)?:\/\/(www\.)?kvetak\.cz/)
			) //comment 3
		) /*comment 4*/
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingRegexpClasses) {
	prepareInput(
R"(
import "cuckoo"

rule rule1 {
	condition:
		cuckoo.network.http_request(/[\w]/) or
			cuckoo.network.http_request(/[\W]/) or
				cuckoo.network.http_request(/[\s]/) or
					cuckoo.network.http_request(/[\S]/) or
						cuckoo.network.http_request(/[\d]/) or
					cuckoo.network.http_request(/[\D]/) or
				cuckoo.network.http_request(/[\b]/) or
			cuckoo.network.http_request(/[\B]/) or
					cuckoo.network.http_request(/[\wa\sa\da\b]/)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(
import "cuckoo"

rule rule1
{
	condition:
		cuckoo.network.http_request(/[\w]/) or
		cuckoo.network.http_request(/[\W]/) or
		cuckoo.network.http_request(/[\s]/) or
		cuckoo.network.http_request(/[\S]/) or
		cuckoo.network.http_request(/[\d]/) or
		cuckoo.network.http_request(/[\D]/) or
		cuckoo.network.http_request(/[\b]/) or
		cuckoo.network.http_request(/[\B]/) or
		cuckoo.network.http_request(/[\wa\sa\da\b]/)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingAlignedComments1) {
	prepareInput(
R"(import "cuckoo"

rule rule1 {
	strings:
		$h0 = { A1 00 01 00 00 01 E1 10 } // comment 0
		$h1 = { B2 00 00 66 E2 02 } // comment 1
		$h2 = { ( 12 | 22 | 33 | ( 44 | ( 55 | ?? ) | 66 ) | 77 | 88 ) } // comment 2
		$h3 = { 00 01 02 03 04 05 }
		$h4 = { C3 [5-6] 00 [5-] 01 5a E1 30 [5-6] 51 } // comment 3
		$h5 = { C3 01 01 5a E1 A2 A1 } // comment 4
		$h6 = { C3 01 01 5a E1 [5-6] A1 }
	condition: // this condition is crucial
		cuckoo.network.http_request(/[\w]/) or // Hello
			true or // from the
				filesize > 50 or // other side!
					all of them // ~'_'~
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(import "cuckoo"

rule rule1
{
	strings:
		$h0 = { A1 00 01 00 00 01 E1 10 }                                // comment 0
		$h1 = { B2 00 00 66 E2 02 }                                      // comment 1
		$h2 = { ( 12 | 22 | 33 | ( 44 | ( 55 | ?? ) | 66 ) | 77 | 88 ) } // comment 2
		$h3 = { 00 01 02 03 04 05 }
		$h4 = { C3 [5-6] 00 [5-] 01 5a E1 30 [5-6] 51 } // comment 3
		$h5 = { C3 01 01 5a E1 A2 A1 }                  // comment 4
		$h6 = { C3 01 01 5a E1 [5-6] A1 }
	condition:                                     // this condition is crucial
		cuckoo.network.http_request(/[\w]/) or // Hello
		true or                                // from the
		filesize > 50 or                       // other side!
		all of them                            // ~'_'~
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingAlignedComments2) {
	prepareInput(
R"(import "cuckoo"

rule abc
{
	// Strings:
	strings:
		// Comment s01
			$s01 = "Hello"
			/* comment s02 */
			$s02 = "Yaragen"
				//comment after s02
	// A very important condition:
	condition:
	true or	(
				// Cuckoo
			$s01 or
	/* Gvma */
			$s02
		)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(import "cuckoo"

rule abc
{
	// Strings:
	strings:
		// Comment s01
		$s01 = "Hello"
		/* comment s02 */
		$s02 = "Yaragen"
		//comment after s02
	// A very important condition:
	condition:
		true or
		(
			// Cuckoo
			$s01 or
			/* Gvma */
			$s02
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingAlignedComments3) {
	prepareInput(
R"(import "cuckoo"

rule abc
{
// Strings:
	strings:
				/* Comment s01 */
			$s01 = "Hello"
			// comment s02
			$s02 = "Yaragen"
		/* comment after s02 */
// A very important condition:
	condition:
	true or	(
// Cuckoo
			$s01 or
	/* Gvma */
			$s02
		)
}
)");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	std::string expected =
R"(import "cuckoo"

rule abc
{
// Strings:
	strings:
		/* Comment s01 */
		$s01 = "Hello"
		// comment s02
		$s02 = "Yaragen"
		/* comment after s02 */
// A very important condition:
	condition:
		true or
		(
			// Cuckoo
			$s01 or
			/* Gvma */
			$s02
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingNewlinesMultipleRules) {
	prepareInput(
R"(/*
This is a comment at the beginning
*/
import "cuckoo"

rule cruel_rule {
	meta:
		author = "Mr. Avastien"
		description = "reliability_test"
		reliability = "brief" // comment
		strain = "Krakonos"  // comment
		type = "roof"  // comment
		severity = "virus"    // comment
		hash = "596EAF3CDD47A710743016E0C032A6EFD0922BA3010C899277E80AA6B6226F85"    // comment
		rule_type = "typical" // comment
	strings:
		$h00 = {
				b8 17 ?? 01
				b8 17 ?? 02
				b8 17 ?? 03 04 //COMMENTARY 1
				b8 17 ?? 23 55       //COMMENTARY 1
				b8 17 ?? 24 a1 //COMMENTARY 1
				b8 17 ?? 25 b5 c6 c1 //COMMENTARY 1
				b8 17 ?? 35
				b8 17 ?? 36 04 //COMMENTARY 2
				b8 17 ?? 37 05 06 //COMMENTARY 2
				b8 17 ?? 47 07 //COMMENTARY 2
				b8 17 ?? 48
				b8 17 ?? 49 11 //COMMENTARY 3
				b8 17 ?? 57 //COMMENTARY 3
				b8 17 ?? 58
				} // 0x00000852 preparing bytes for sending semi-valid SMB response
		$s00 = "str 123" // 0x17
		$s01 = "string 234567"  // 0x005
		$s02 = "basic for loop" // 0
	condition:
		any of ($s0*) or
		$h00
}

rule cruel_rule_2 {
	meta:
		author = "Mr. Avastien"
	strings:
		$s00 = "str 123" // 0x17
		$s01 = "string 234567"  // 0x005
		$s02 = "basic for loop" // 0
	condition:
		false or ($s00 and $s01 and $s02 and
		cuckoo.network.http_request(/[\w]/))
})");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

std::string expected = R"(/*
This is a comment at the beginning
*/
import "cuckoo"

rule cruel_rule
{
	meta:
		author = "Mr. Avastien"
		description = "reliability_test"
		reliability = "brief"                                                     // comment
		strain = "Krakonos"                                                       // comment
		type = "roof"                                                             // comment
		severity = "virus"                                                        // comment
		hash = "596EAF3CDD47A710743016E0C032A6EFD0922BA3010C899277E80AA6B6226F85" // comment
		rule_type = "typical"                                                     // comment
	strings:
		$h00 = {
			b8 17 ?? 01
			b8 17 ?? 02
			b8 17 ?? 03 04       //COMMENTARY 1
			b8 17 ?? 23 55       //COMMENTARY 1
			b8 17 ?? 24 a1       //COMMENTARY 1
			b8 17 ?? 25 b5 c6 c1 //COMMENTARY 1
			b8 17 ?? 35
			b8 17 ?? 36 04    //COMMENTARY 2
			b8 17 ?? 37 05 06 //COMMENTARY 2
			b8 17 ?? 47 07    //COMMENTARY 2
			b8 17 ?? 48
			b8 17 ?? 49 11 //COMMENTARY 3
			b8 17 ?? 57    //COMMENTARY 3
			b8 17 ?? 58
		}                       // 0x00000852 preparing bytes for sending semi-valid SMB response
		$s00 = "str 123"        // 0x17
		$s01 = "string 234567"  // 0x005
		$s02 = "basic for loop" // 0
	condition:
		any of ($s0*) or
		$h00
}

rule cruel_rule_2
{
	meta:
		author = "Mr. Avastien"
	strings:
		$s00 = "str 123"        // 0x17
		$s01 = "string 234567"  // 0x005
		$s02 = "basic for loop" // 0
	condition:
		false or
		(
			$s00 and
			$s01 and
			$s02 and
			cuckoo.network.http_request(/[\w]/)
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingRemoveRedundantBlankLines) {
	prepareInput(
R"(rule rule_name {

	meta:


		key = "value"



	condition:




		true




})");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

std::string expected = R"(rule rule_name
{
	meta:
		key = "value"
	condition:
		true
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingRemoveRedundantBlankLines2) {
	prepareInput(
R"(
import "cuckoo"

rule rule_name_1 {

	meta:

		title = "some unique title"

		author = "Mr Avastien"

	strings:

		$string1 = " Brandenburger Tor"

		$string2 = "Fernsehrturm" wide

		$string3 =   { AA ?? }

	variables:

		var1 = "a string value"

		var2 = 25.4

	condition:

		all of them and cuckoo.registry.key_access(/abc+/)

}

rule rule_name_2 {

	meta:

		title = "the very same title"

		author = "Mr Avastien"

	strings:

		$string1 = " burger"

		$string2 = "Fernsehr"

		$string3 =   { BB ?? }

	variables:

		var1 = 1 + 4

		var2 = true

		var3 = 3.4

	condition:

		all of them

})");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());
	const auto& rule1 = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("all", rule1->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ(")", rule1->getCondition()->getLastTokenIt()->getPureText());

std::string expected = R"(
import "cuckoo"

rule rule_name_1
{
	meta:
		title = "some unique title"
		author = "Mr Avastien"
	strings:
		$string1 = " Brandenburger Tor"
		$string2 = "Fernsehrturm" wide
		$string3 = { AA ?? }
	variables:
		var1 = "a string value"
		var2 = 25.4
	condition:
		all of them and
		cuckoo.registry.key_access(/abc+/)
}

rule rule_name_2
{
	meta:
		title = "the very same title"
		author = "Mr Avastien"
	strings:
		$string1 = " burger"
		$string2 = "Fernsehr"
		$string3 = { BB ?? }
	variables:
		var1 = 1 + 4
		var2 = true
		var3 = 3.4
	condition:
		all of them
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingCommentInsideHexstringOnNewline) {
	prepareInput(
R"(rule cruel_rule
{
	strings:
		$h00 = {
			// comment inside hex on the beginning
			b8 17 ?? 01
			// comment inside hex in the middle
			b8 17 ?? 03 04
			b8 17 ?? 23 55
			// comment inside hex in the end
			}
	condition:
		true
})");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

std::string expected = R"(rule cruel_rule
{
	strings:
		$h00 = {
			// comment inside hex on the beginning
			b8 17 ?? 01
			// comment inside hex in the middle
			b8 17 ?? 03 04
			b8 17 ?? 23 55
			// comment inside hex in the end
		}
	condition:
		true
}
)";
	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingNoSpaceBeforeNewLine) {
	prepareInput(
R"(import "math"

rule rule1
{
	condition:
		true and
		(
			for any i in (	1, 2, 3,
									4, 5, 6,
									7 ):
		(
			true)
		)
})");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

std::string expected = R"(import "math"

rule rule1
{
	condition:
		true and
		(
			for any i in (
				1, 2, 3,
				4, 5, 6,
				7
			) :
			(
				true
			)
		)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingOfOnelineRule) {
	prepareInput(
R"(rule oneline_rule { /*COMMENT 1*/ meta: author = "Mr. Avastien"    /*COMMENT 2*/    description = "reliability_test"    /*COMMENT 3*/      strings: $s00 = "str 123"     /*COMMENT 4*/    $s01 = "string 234567"   /*COMMENT 5*/    condition: /*COMMENT 6*/  any of ($s0*) /*COMMENT 7*/ })");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

std::string expected = R"(rule oneline_rule
{ /*COMMENT 1*/
	meta:
		author = "Mr. Avastien" /*COMMENT 2*/
		description = "reliability_test" /*COMMENT 3*/
	strings:
		$s00 = "str 123" /*COMMENT 4*/
		$s01 = "string 234567" /*COMMENT 5*/
	condition: /*COMMENT 6*/
		any of ($s0*) /*COMMENT 7*/
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingOfTwoOnelineRules) {
	prepareInput(
R"(rule oneline_rule { /*COMMENT 1*/ meta: author = "Mr. Avastien"    /*COMMENT 2*/    description = "reliability_test"    /*COMMENT 3*/      strings: $s00 = "str 123"     /*COMMENT 4*/    $s01 = "string 234567"   /*COMMENT 5*/    condition: /*COMMENT 6*/  any of ($s0*) /*COMMENT 7*/ } rule oneline_rule_2 { /*COMMENT 1*/ meta: author = "Mr. Avastien"    /*COMMENT 2*/    description = "reliability_test"    /*COMMENT 3*/      strings: $s00 = "str 123"     /*COMMENT 4*/    $s01 = "string 234567"   /*COMMENT 5*/    condition: /*COMMENT 6*/  any of ($s0*) /*COMMENT 7*/ })");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

std::string expected = R"(rule oneline_rule
{ /*COMMENT 1*/
	meta:
		author = "Mr. Avastien" /*COMMENT 2*/
		description = "reliability_test" /*COMMENT 3*/
	strings:
		$s00 = "str 123" /*COMMENT 4*/
		$s01 = "string 234567" /*COMMENT 5*/
	condition: /*COMMENT 6*/
		any of ($s0*) /*COMMENT 7*/
}

rule oneline_rule_2
{ /*COMMENT 1*/
	meta:
		author = "Mr. Avastien" /*COMMENT 2*/
		description = "reliability_test" /*COMMENT 3*/
	strings:
		$s00 = "str 123" /*COMMENT 4*/
		$s01 = "string 234567" /*COMMENT 5*/
	condition: /*COMMENT 6*/
		any of ($s0*) /*COMMENT 7*/
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
AutoformattingVariableInCondition) {
	prepareInput(
R"(rule rule1
{
	variables:
		int_var = 1
	condition:
		int_var and
		(	int_var<3 )
})");
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

std::string expected = R"(rule rule1
{
	variables:
		int_var = 1
	condition:
		int_var and
		(int_var < 3)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RenameReferencedRuleWorks) {
	prepareInput(
R"(
rule abc
{
	condition:
		true
}

rule def
{
	condition:
		abc
}
)"
);
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());

	const auto& rule1 = driver.getParsedFile().getRules()[0];
	rule1->setName("XYZ");
	EXPECT_EQ(rule1->getName(), "XYZ");
	const auto& rule2 = driver.getParsedFile().getRules()[1];
	EXPECT_EQ(rule2->getCondition()->getText(), "XYZ");

std::string expected = R"(
rule XYZ
{
	condition:
		true
}

rule def
{
	condition:
		XYZ
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RenameStringWorks1) {
	prepareInput(
R"(
rule abc
{
	strings:
		$s07 = "abc string"
	condition:
		$s07
}
)"
);
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(input_text, driver.getParsedFile().getTextFormatted());

	const auto& rule = driver.getParsedFile().getRules()[0];
	ASSERT_EQ(1u, rule->getStrings().size());
	std::shared_ptr<String> s;
	ASSERT_TRUE(rule->getStringsTrie()->find("$s07", s));
	s->setIdentifier("$s1");

	std::string expected = R"(
rule abc
{
	strings:
		$s1 = "abc string"
	condition:
		$s1
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
	auto condition = rule->getCondition();
	EXPECT_EQ(condition->getText(), "$s1");
	(std::static_pointer_cast<StringExpression>(condition))->setId("$s2");

	expected = R"(
rule abc
{
	strings:
		$s2 = "abc string"
	condition:
		$s2
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RenameStringWorks2) {
	prepareInput(
R"(
rule abc
{
	strings:
		$s07 = "abc string"
	condition:
		$s07 and
		#s07 == 5 or
		(
			(@s07 > 5) and
			(@s07[0] > 100)
		) and
		$s07 at entrypoint and
		$s07 in (10 .. 20)
}
)"
);
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());

	const auto& rule = driver.getParsedFile().getRules()[0];
	ASSERT_EQ(1u, rule->getStrings().size());
	std::shared_ptr<String> s;
	ASSERT_TRUE(rule->getStringsTrie()->find("$s07", s));
	s->setIdentifier("$s1");

	EXPECT_EQ(rule->getCondition()->getText(), "$s1 and #s1 == 5 or ((@s1 > 5) and (@s1[0] > 100)) and $s1 at entrypoint and $s1 in (10 .. 20)");

	std::string expected = R"(
rule abc
{
	strings:
		$s1 = "abc string"
	condition:
		$s1 and
		#s1 == 5 or
		(
			(@s1 > 5) and
			(@s1[0] > 100)
		) and
		$s1 at entrypoint and
		$s1 in (10 .. 20)
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}


TEST_F(ParserTests,
RenameStringWorks3) {
	prepareInput(
R"(
rule abc
{
	strings:
		$s07 = "abc string"
	condition:
		for any of ($s07) : ( $ at entrypoint )
}
)"
);
	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());

	const auto& rule = driver.getParsedFile().getRules()[0];
	ASSERT_EQ(1u, rule->getStrings().size());
	std::shared_ptr<String> s;
	ASSERT_TRUE(rule->getStringsTrie()->find("$s07", s));
	s->setIdentifier("$s1");

	EXPECT_EQ(rule->getCondition()->getText(), "for any of ($s1) : ( $ at entrypoint )");

	std::string expected = R"(
rule abc
{
	strings:
		$s1 = "abc string"
	condition:
		for any of ($s1) : ( $ at entrypoint )
}
)";

	EXPECT_EQ(expected, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringXorModifierWithArguments) {
	prepareInput(
R"(
rule string_xor_modifier_with_arguments {
	strings:
		$s01 = "Hello" xor
		$s02 = "Hello" xor(123)
		$s03 = "Hello" xor(1-255)
		$s04 = "Hello" xor /* Comment */ (1-255)
	condition:
		all of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(4u, strings.size());

	auto string1 = strings[0];
	EXPECT_EQ(string1->getModifiers().size(), 1);
	EXPECT_EQ(string1->getModifiersText(), " xor");

	auto string2 = strings[1];
	EXPECT_EQ(string2->getModifiers().size(), 1);
	EXPECT_EQ(string2->getModifiersText(), " xor(123)");

	auto string3 = strings[2];
	EXPECT_EQ(string3->getModifiers().size(), 1);
	EXPECT_EQ(string3->getModifiersText(), " xor(1-255)");

	auto string4 = strings[3];
	EXPECT_EQ(string4->getModifiers().size(), 1);
	EXPECT_EQ(string4->getModifiersText(), " xor(1-255)");

	EXPECT_EQ(R"(
rule string_xor_modifier_with_arguments
{
	strings:
		$s01 = "Hello" xor
		$s02 = "Hello" xor(123)
		$s03 = "Hello" xor(1-255)
		$s04 = "Hello" xor /* Comment */(1-255)
	condition:
		all of them
}
)", driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringXorModifierWithOutOfBoundsKey) {
	prepareInput(
R"(
rule string_xor_modifier_with_out_of_bounds_key {
	strings:
		$s01 = "Hello" xor(256)
	condition:
		all of them
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const YaramodError& err)
	{
		EXPECT_EQ("Error: XOR string modifier key is out of allowed range", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
StringXorModifierWithOutOfBoundsLowerKey) {
	prepareInput(
R"(
rule string_xor_modifier_with_out_of_bounds_lower_key {
	strings:
		$s01 = "Hello" xor(256-256)
	condition:
		all of them
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const YaramodError& err)
	{
		EXPECT_EQ("Error: XOR string modifier key is out of allowed range", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
StringXorModifierWithOutOfBoundsHigherKey) {
	prepareInput(
R"(
rule string_xor_modifier_with_out_of_bounds_higher_key {
	strings:
		$s01 = "Hello" xor(1-256)
	condition:
		all of them
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const YaramodError& err)
	{
		EXPECT_EQ("Error: XOR string modifier key is out of allowed range", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
StringXorModifierWithLowerBoundGreaterThanHigherBound) {
	prepareInput(
R"(
rule string_xor_modifier_with_out_of_bounds_higher_key {
	strings:
		$s01 = "Hello" xor(2-1)
	condition:
		all of them
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const YaramodError& err)
	{
		EXPECT_EQ("Error: XOR string modifier has lower bound of key greater then higher bound", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
PrivateStringModifier) {
	prepareInput(
R"(
rule private_string_modifier
{
	strings:
		$s01 = "Hello" private
		$s02 = { AA BB CC DD } private
		$s03 = /Hello/i private
	condition:
		all of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(3u, strings.size());

	auto string1 = strings[0];
	EXPECT_EQ(string1->getModifiers().size(), 1);
	EXPECT_EQ(string1->getModifiersText(), " private");
	EXPECT_TRUE(string1->isPrivate());

	auto string2 = strings[1];
	EXPECT_EQ(string2->getModifiers().size(), 1);
	EXPECT_EQ(string2->getModifiersText(), " private");
	EXPECT_TRUE(string2->isPrivate());

	auto string3 = strings[2];
	EXPECT_EQ(string3->getModifiers().size(), 1);
	EXPECT_EQ(string3->getModifiersText(), " private");
	EXPECT_TRUE(string3->isPrivate());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
UnexpectedEndOfFile) {
	prepareInput(
R"(
rule unexpected_end_of_file
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 3.1: Syntax error: Unexpected @end, expected one of {, :", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
ReuseOfParserAfterError) {
	prepareInput(
R"(
rule unexpected_end_of_file
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 3.1: Syntax error: Unexpected @end, expected one of {, :", err.getErrorMessage());
	}

	prepareInput(
R"(
rule empty_rule
{
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("empty_rule", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_EQ(0u, rule->getMetas().size());
	EXPECT_TRUE(rule->getStrings().empty());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
DefinedExpression) {
	prepareInput(
R"(
rule defined_expr
{
	condition:
		defined 1
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ("defined 1", rule->getCondition()->getText());
	EXPECT_EQ("defined", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("1", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
IequalsExpression) {
	prepareInput(
R"(import "pe"

rule iequals_expr
{
	condition:
		pe.sections[0].name iequals ".TEXT"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ("pe.sections[0].name iequals \".TEXT\"", rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("\".TEXT\"", rule->getCondition()->getLastTokenIt()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParsePeSignaturesXAlgorithmOID) {
	prepareInput(
R"(import "pe"

rule test_rule
{
	condition:
		pe.signatures[0].algorithm_oid == "1.2.840.113549.1.1.11"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseELFDynsym) {
	prepareInput(
		R"(import "elf"

rule test_rule
{
	condition:
		elf.dynsym_entries == 1 or
		elf.dynsym[0].name == "name" or
		elf.dynsym[0].value == "value" or
		elf.dynsym[0].size == 2 or
		elf.dynsym[0].type == elf.STT_NOTYPE or
		elf.dynsym[0].type == elf.STT_OBJECT or
		elf.dynsym[0].type == elf.STT_FUNC or
		elf.dynsym[0].type == elf.STT_SECTION or
		elf.dynsym[0].type == elf.STT_FILE or
		elf.dynsym[0].type == elf.STT_COMMON or
		elf.dynsym[0].type == elf.STT_TLS or
		elf.dynsym[0].bind == 3 or
		elf.dynsym[0].shndx == 3
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParsePercentage1Error) {
	prepareInput(
		R"(rule test_rule
{
	strings:
		$a = "AXS"
	condition:
		101% of them
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 6.6: Percentage must be between 1 and 100 (inclusive). Got 101.", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
ParsePercentage2Error) {
	prepareInput(
		R"(rule test_rule
{
	strings:
		$a = "ERS"
	condition:
		0% of them
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 6.4: Percentage must be between 1 and 100 (inclusive). Got 0.", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
ParsePercentage3) {
	prepareInput(
		R"(rule test_rule
{
	strings:
		$a = "dummy"
	condition:
		50% of them
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParsePercentage4) {
	prepareInput(
		R"(rule test_rule
{
	strings:
		$a = "no"
		$a2 = "time"
	condition:
		1050 % 100 of them
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParsePercentage5) {
	prepareInput(
		R"(rule test_rule
{
	strings:
		$a = "no"
		$a2 = "time"
	condition:
		100% of them
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParsePercentage6) {
	prepareInput(
		R"(import "pe"

rule test_rule
{
	strings:
		$a = "no"
		$a2 = "time"
	condition:
		(25 * pe.sections[0].number_of_relocations)% of them
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParsePercentage7) {
	prepareInput(
		R"(import "pe"

rule test_rule
{
	strings:
		$a = "no"
		$a2 = "time"
	condition:
		pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].size% of them
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseOfRule) {
	prepareInput(
		R"(rule rule1
{
	condition:
		true
}

rule rule2
{
	condition:
		true
}

rule rule3
{
	condition:
		true
}

rule test_rule
{
	condition:
		any of (rule1, rule2, rule3)
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(4u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
ParseOfRuleInvalid) {
	prepareInput(
		R"(rule test_rule
{
	condition:
		any of (test_rule)
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ("Error at 4.11-19: Unrecognized identifier 'test_rule' referenced", err.getErrorMessage());
		EXPECT_EQ(")", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}

//TEST_F(ParserTests,
//ParseOfRuleWildcard) {
//	prepareInput(
//		R"(rule rule1
//{
//	condition:
//		true
//}
//
//rule rule2
//{
//	condition:
//		true
//}
//
//rule rule3
//{
//	condition:
//		true
//}
//
//rule test_rule
//{
//	condition:
//		any of (ru*)
//}
//)");
//
//	EXPECT_TRUE(driver.parse(input));
//	ASSERT_EQ(4u, driver.getParsedFile().getRules().size());
//
//	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
//}

//TEST_F(ParserTests,
//ParseOfRuleWildcardInvalid) {
//	prepareInput(
//		R"(rule test_rule
//{
//	condition:
//		any of (test*)
//}
//)");
//
//	try
//	{
//		driver.parse(input);
//		FAIL() << "Parser did not throw an exception.";
//	}
//	catch (const ParserError& err)
//	{
//		EXPECT_EQ("Error at 4.11-14: No rule matched with wildcard 'test*'", err.getErrorMessage());
//		EXPECT_EQ(")", driver.getParsedFile().getTokenStream()->back().getPureText());
//	}
//}

TEST_F(ParserTests,
ParseAmbiguousWithIdWildcard) {
	prepareInput(
		R"(rule x
{
	condition:
		true
}

rule rule1
{
	condition:
		x*1
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ("Error at 10.4: operator '*' expects integer or float on the left-hand side", err.getErrorMessage());
		EXPECT_EQ("}", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}

TEST_F(ParserTests,
ExpressionUids) {
	prepareInput(
		R"(rule ExampleRule1
{
	strings:
		$my_text_string = "text here" private
		$my_hex_string = { E2 34 A1 C8 23 FB }
		$a = "text1"
		$b = "text2"
		$c = "text3"
		$d = "text4"
	condition:
		($a or $b) and ($c or $d)
		or (#a == 6 and #b > 10) and
		any of them
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	auto yaraFile = driver.getParsedFile();
	ASSERT_TRUE(yaraFile.hasRules());
	ASSERT_EQ(21, yaraFile.getRules()[0]->getCondition()->getUid());
}

TEST_F(ParserTests,
OctalIntegerWorks) {
	prepareInput(
		R"(rule ExampleRule1
{
	condition:
		0o777 and 0o10
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	auto yaraFile = driver.getParsedFile();
	ASSERT_TRUE(yaraFile.hasRules());

	auto condition = yaraFile.getRules()[0]->getCondition();
	auto expAnd = std::static_pointer_cast<const AndExpression>(condition);
	auto left = std::static_pointer_cast<const IntLiteralExpression>(expAnd->getLeftOperand());
	auto right = std::static_pointer_cast<const IntLiteralExpression>(expAnd->getRightOperand());
	EXPECT_EQ(left->getText(), "0o777");
	EXPECT_EQ(right->getText(), "0o10");
	EXPECT_EQ(left->getValue(), 511);
	EXPECT_EQ(right->getValue(), 8);
}

TEST_F(ParserTests,
Yara423FunctionsWorks) {
	prepareInput(
		R"(import "math"
import "pe"

rule yara423_functions {
	condition:
		pe.import_details[0].functions[0].rva == 0 and
		pe.delayed_import_details[0].functions[0].rva == 0 and
		math.to_int("0") == 0 and
		math.to_int("0", 10) == 0 and
		math.to_string(0) == "0" and
		math.to_string(0, 10) == "0"
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	auto yaraFile = driver.getParsedFile();
	ASSERT_TRUE(yaraFile.hasRules());

	auto condition = yaraFile.getRules()[0]->getCondition();
	EXPECT_EQ(condition->getText(), "pe.import_details[0].functions[0].rva == 0 and pe.delayed_import_details[0].functions[0].rva == 0 and math.to_int(\"0\") == 0 and math.to_int(\"0\", 10) == 0 and math.to_string(0) == \"0\" and math.to_string(0, 10) == \"0\"");
}

TEST_F(ParserTests,
HexStringNotWorks) {
	prepareInput(
		R"(rule hex_string_not
{
	strings:
		$h00 = { ~01 }
		$h01 = { ~0? }
		$h02 = { ~?0 }
		$h03 = { ( 10 ~1? 1A | 20 ~?1 ~31 ) }
	condition:
		all of them
}
)");


	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	auto yaraFile = driver.getParsedFile();
	ASSERT_TRUE(yaraFile.hasRules());

  auto rule = yaraFile.getRules()[0];
  ASSERT_EQ(rule->getStrings().size(), 4);

  auto strings = rule->getStrings();
	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$h00", hexString->getIdentifier());
	EXPECT_EQ("{ ~01 }", hexString->getText());

  hexString = strings[1];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$h01", hexString->getIdentifier());
	EXPECT_EQ("{ ~0? }", hexString->getText());

  hexString = strings[2];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$h02", hexString->getIdentifier());
	EXPECT_EQ("{ ~?0 }", hexString->getText());

  hexString = strings[3];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$h03", hexString->getIdentifier());
	EXPECT_EQ("{ ( 10 ~1? 1A | 20 ~?1 ~31 ) }", hexString->getText());

  EXPECT_EQ(R"(rule hex_string_not
{
	strings:
		$h00 = { ~01 }
		$h01 = { ~0? }
		$h02 = { ~?0 }
		$h03 = { ( 10 ~1? 1A | 20 ~?1 ~31 ) }
	condition:
		all of them
}
)", yaraFile.getTextFormatted());
}

TEST_F(ParserTests,
IcontainsExpression) {
	prepareInput(
R"(import "pe"

rule icontains_expr
{
	condition:
		pe.sections[0].name icontains ".TEXT"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ("pe.sections[0].name icontains \".TEXT\"", rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("\".TEXT\"", rule->getCondition()->getLastTokenIt()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
IendsWithExpression) {
	prepareInput(
R"(import "pe"

rule iendswith_expr
{
	condition:
		pe.sections[0].name iendswith ".TEXT"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ("pe.sections[0].name iendswith \".TEXT\"", rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("\".TEXT\"", rule->getCondition()->getLastTokenIt()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
IstartsWithExpression) {
	prepareInput(
R"(import "pe"

rule istartswith_expr
{
	condition:
		pe.sections[0].name istartswith ".TEXT"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ("pe.sections[0].name istartswith \".TEXT\"", rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("\".TEXT\"", rule->getCondition()->getLastTokenIt()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StartsWithExpression) {
	prepareInput(
R"(import "pe"

rule startswith_expr
{
	condition:
		pe.sections[0].name startswith ".TEXT"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ("pe.sections[0].name startswith \".TEXT\"", rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("\".TEXT\"", rule->getCondition()->getLastTokenIt()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
EndsWithExpression) {
	prepareInput(
R"(import "pe"

rule endswith_expr
{
	condition:
		pe.sections[0].name endswith ".TEXT"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	EXPECT_EQ("pe.sections[0].name endswith \".TEXT\"", rule->getCondition()->getText());
	EXPECT_EQ("pe", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("\".TEXT\"", rule->getCondition()->getLastTokenIt()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
StringModuleWorks) {
	prepareInput(
R"(
import "string"

rule string_module
{
	condition:
		string.to_int("1234") == 1234 and
		string.to_int("-10") == -10 and
		string.to_int("-010") == -8 and
		string.to_int("011", 8) == 9 and
		string.to_int("-011", 0) == -9 and
		string.length("AXSx00ERS") == 7
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(string.to_int("1234") == 1234 and string.to_int("-10") == -10 and string.to_int("-010") == -8 and string.to_int("011", 8) == 9 and string.to_int("-011", 0) == -9 and string.length("AXSx00ERS") == 7)", rule->getCondition()->getText());
	EXPECT_EQ("string", rule->getCondition()->getFirstTokenIt()->getPureText());
	EXPECT_EQ("7", rule->getCondition()->getLastTokenIt()->getPureText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
IncompleteModeWithModulesWorks) {
	prepareInput(
R"(
rule module_rule
{
	condition:
		pe.import_details[0].rva == 0x1234 and
		string.to_int("1234") == 1234
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(pe.import_details[0].rva == 0x1234 and string.to_int("1234") == 1234)", rule->getCondition()->getText());
	EXPECT_EQ(2u, driver.getParsedFile().getImports().size());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
WithExpressionWorks) {
	prepareInput(
R"(
rule with_expression
{
	condition:
		with a = 1, b = 2, c = 3 + 5 : (
			a + b > a + c
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(with a = 1, b = 2, c = 3 + 5 : (a + b > a + c))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
WithExpressionVariableOutOfScope) {
	prepareInput(
		R"(rule test_rule
{
	condition:
		with a = 1 : (
			a > 2
		) and a < 1
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ("Error at 6.9: Unrecognized identifier 'a' referenced", err.getErrorMessage());
		EXPECT_EQ("<", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}


TEST_F(ParserTests,
ExpressionArrayWorks) {
	prepareInput(
R"(
rule expression_array
{
	condition:
		any of (1, 2, 3)
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(any of (1, 2, 3))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
MixedWildcardExpressionArrayNotAllowed) {
	prepareInput(
		R"(rule mixed_expression_array
{
	strings:
		$s01 = "abc"
		$s02 = "def"
	condition:
		any of ($s*, true)
}
)");

	try
	{
		driver.parse(input);
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ("Error at 7.20: unexpected expression, expected either string or string wildcard within string set", err.getErrorMessage());
		EXPECT_EQ(")", driver.getParsedFile().getTokenStream()->back().getPureText());
	}
}

TEST_F(ParserTests,
ExpressionArrayResultsInIterableExpressionWithStringFirst) {
	prepareInput(
R"(
rule expression_array
{
	strings:
		$hello = "Hello"
	condition:
		any of ($hello, true)
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(any of ($hello, true))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());

	ASSERT_NE(rule->getCondition()->as<OfExpression>(), nullptr);
	ASSERT_NE(rule->getCondition()->as<OfExpression>()->getIterable()->as<IterableExpression>(), nullptr);
}

TEST_F(ParserTests,
ExpressionArrayResultsInIterableExpressionWithStringLast) {
	prepareInput(
R"(
rule expression_array
{
	strings:
		$hello = "Hello"
	condition:
		any of (true, $hello)
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(any of (true, $hello))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());

	ASSERT_NE(rule->getCondition()->as<OfExpression>(), nullptr);
	ASSERT_NE(rule->getCondition()->as<OfExpression>()->getIterable()->as<IterableExpression>(), nullptr);
}

TEST_F(ParserTests,
ExpressionArrayResultsInStringSet) {
	prepareInput(
R"(
rule expression_array
{
	strings:
		$hello1 = "Hello"
		$hello2 = "Ahoj"
	condition:
		any of ($hello1, $hello2)
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(any of ($hello1, $hello2))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());

	ASSERT_NE(rule->getCondition()->as<OfExpression>(), nullptr);
	ASSERT_NE(rule->getCondition()->as<OfExpression>()->getIterable()->as<SetExpression>(), nullptr);
}

TEST_F(ParserTests,
ExpressionArrayNestedTypes) {
	prepareInput(
R"(
rule expression_array
{
	strings:
		$hello1 = "Hello"
		$hello2 = "Ahoj"
	condition:
		any of (
			any of ($hello*),
			any of ($hello1, $hello2),
			true
		)
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(any of (any of ($hello*), any of ($hello1, $hello2), true))", rule->getCondition()->getText());

	EXPECT_EQ(input_text, driver.getParsedFile().getTextFormatted());

	ASSERT_NE(rule->getCondition()->as<OfExpression>(), nullptr);
	ASSERT_NE(rule->getCondition()->as<OfExpression>()->getIterable()->as<IterableExpression>(), nullptr);

	auto parent_itr = rule->getCondition()->as<OfExpression>()->getIterable()->as<IterableExpression>();
	ASSERT_NE(parent_itr->getElements()[0]->as<OfExpression>(), nullptr);
	ASSERT_NE(parent_itr->getElements()[0]->as<OfExpression>()->getIterable()->as<SetExpression>(), nullptr);
	ASSERT_NE(parent_itr->getElements()[1]->as<OfExpression>(), nullptr);
	ASSERT_NE(parent_itr->getElements()[1]->as<OfExpression>()->getIterable()->as<SetExpression>(), nullptr);
	ASSERT_NE(parent_itr->getElements()[2]->as<BoolLiteralExpression>(), nullptr);
}

TEST_F(ParserTests,
RemoveVariablesNone) {
	prepareInput(
R"(
rule remove_variables
{
	condition:
		false
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	rule->removeVariables();

	EXPECT_EQ(0u, rule->getVariables().size());
	EXPECT_EQ(R"(rule remove_variables {
	condition:
		false
})", rule->getText());

	EXPECT_EQ(R"(
rule remove_variables
{
	condition:
		false
}
)", driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RemoveVariables) {
	prepareInput(
R"(
rule remove_variables
{
	strings:
		$s01 = "abc"
	variables:
		a = 1
		b = 2
		c = a + b
	condition:
		$s01
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	rule->removeVariables();

	EXPECT_EQ(0u, rule->getVariables().size());
	EXPECT_EQ(R"(rule remove_variables {
	strings:
		$s01 = "abc"
	condition:
		$s01
})", rule->getText());

	EXPECT_EQ(R"(
rule remove_variables
{
	strings:
		$s01 = "abc"
	condition:
		$s01
}
)", driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RemoveVariablesWithStringsInterleaved) {
	prepareInput(
R"(
rule remove_variables
{
	variables:
		a = 1
		b = 2
		c = a + b
	strings:
		$s01 = "abc"
	condition:
		$s01
}
)");

	EXPECT_TRUE(driver.parse(input, ParserMode::Incomplete));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	rule->removeVariables();

	EXPECT_EQ(0u, rule->getVariables().size());
	EXPECT_EQ(R"(rule remove_variables {
	strings:
		$s01 = "abc"
	condition:
		$s01
})", rule->getText());

	EXPECT_EQ(R"(
rule remove_variables
{
	strings:
		$s01 = "abc"
	condition:
		$s01
}
)", driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
RegexpRangeWithWhitespaces) {
	prepareInput(
R"(
rule regexp_range_with_whitespaces
{
	strings:
		$1 = /ab{  1  ,  2  }/
	condition:
		true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_range_with_whitespaces", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp0 = strings[0];
	EXPECT_TRUE(regexp0->isRegexp());
	EXPECT_EQ("$1", regexp0->getIdentifier());
	EXPECT_EQ("/ab{1,2}/", regexp0->getText());

	EXPECT_EQ(R"(
rule regexp_range_with_whitespaces
{
	strings:
		$1 = /ab{1,2}/
	condition:
		true
}
)", driver.getParsedFile().getTextFormatted());
}

TEST_F(ParserTests,
FormattingInExpressionArraysNotBroken) {
	prepareInput(
R"(
import "cuckoo"
import "math"
import "pe"

rule formatting_in_expression_arrays_not_broken
{
	condition:
		2 of (
			math.min(cuckoo.sync.mutex(/abc/), 100 + ( 220 + 300 )),
			pe.imphash() contains "a",
			any of (
				math.min(cuckoo.sync.mutex(/abc/), 100 + ( 220 + 300 )),
				math.min(cuckoo.sync.mutex(/abc/), 100 + ( 220 + 300 ))
			)
		) or
		for any i in (1 + 2, 2, 3, 4, 5) : ( true )
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	EXPECT_EQ(driver.getParsedFile().getTextFormatted(), R"(
import "cuckoo"
import "math"
import "pe"

rule formatting_in_expression_arrays_not_broken
{
	condition:
		2 of (
			math.min(cuckoo.sync.mutex(/abc/), 100 + ( 220 + 300 )),
			pe.imphash() contains "a",
			any of (
				math.min(cuckoo.sync.mutex(/abc/), 100 + ( 220 + 300 )),
				math.min(cuckoo.sync.mutex(/abc/), 100 + ( 220 + 300 ))
			)
		) or
		for any i in (1 + 2, 2, 3, 4, 5) : ( true )
}
)");
}

}
}
