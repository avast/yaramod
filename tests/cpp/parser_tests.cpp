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
	void prepareInput(const std::string& inputText)
	{
		input.str(std::string());
		input.clear();
		input << inputText;
	}

	std::stringstream input;
};

TEST_F(ParserTests,
EmptyInputWorks) {
	prepareInput("");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
}

TEST_F(ParserTests,
EmptyRuleWorks) {
	prepareInput(
R"(
rule empty_rule {
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("empty_rule", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_EQ(0u, rule->getMetas().size());
	EXPECT_TRUE(rule->getStrings().empty());
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

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ("Error at 7.6-20: Redefinition of rule 'same_named_rule'", err.getErrorMessage());
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

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_tags", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());
	EXPECT_EQ(0u, rule->getMetas().size());
	EXPECT_TRUE(rule->getStrings().empty());

	std::vector<std::string> expected = { "Tag1", "Tag2", "Tag3" };
	EXPECT_EQ(expected, rule->getTags());
}

TEST_F(ParserTests,
RuleWithMetasWorks) {
	prepareInput(
R"(
rule rule_with_metas {
	meta:
		str_meta = "string meta"
		int_meta = 42
		bool_meta = true
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexAndDecimalIntegersArePreservedWorks) {
	prepareInput(
R"(
rule hex_and_decimal_integers_are_preserved {
	meta:
		hex_meta = 0x42
		dec_meta = 42
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
	EXPECT_EQ("42", decMeta.getValue().getText());
}

TEST_F(ParserTests,
RuleWithPlainTextStringsWorks) {
	prepareInput(
R"(
rule rule_with_plain_strings {
	strings:
		$1 = "Hello World!"
		$2 = "Bye World."
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
MultipleRulesWorks) {
	prepareInput(
R"(
rule rule_1 {
	strings:
		$1 = "String from Rule 1"
	condition:
		true
}

rule rule_2 {
	strings:
		$1 = "String from Rule 2"
	condition:
		true
}

rule rule_3 {
	strings:
		$1 = "String from Rule 3"
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RuleWithPlainTextStringWithModifiersWorks) {
	prepareInput(
R"(
rule rule_with_plain_strings {
	strings:
		$1 = "Hello World!" nocase wide
		$2 = "Bye World." fullword
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("rule_with_plain_strings", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(2u, strings.size());

	auto helloWorld = strings[0];
	ASSERT_TRUE(helloWorld->isPlain());
	EXPECT_EQ("$1", helloWorld->getIdentifier());
	EXPECT_EQ("\"Hello World!\" wide nocase", helloWorld->getText());
	EXPECT_FALSE(static_cast<const PlainString*>(helloWorld)->isAscii());
	EXPECT_TRUE(static_cast<const PlainString*>(helloWorld)->isWide());
	EXPECT_TRUE(static_cast<const PlainString*>(helloWorld)->isNocase());
	EXPECT_FALSE(static_cast<const PlainString*>(helloWorld)->isFullword());

	auto byeWorld = strings[1];
	ASSERT_TRUE(byeWorld->isPlain());
	EXPECT_EQ("$2", byeWorld->getIdentifier());
	EXPECT_EQ("\"Bye World.\" fullword", byeWorld->getText());
	EXPECT_TRUE(static_cast<const PlainString*>(byeWorld)->isAscii());
	EXPECT_FALSE(static_cast<const PlainString*>(byeWorld)->isWide());
	EXPECT_FALSE(static_cast<const PlainString*>(byeWorld)->isNocase());
	EXPECT_TRUE(static_cast<const PlainString*>(byeWorld)->isFullword());
}

TEST_F(ParserTests,
HexStringWithPlainNibblesWorks) {
	prepareInput(
R"(
rule hex_string_with_plain_nibbles {
	strings:
		$1 = { 01 23 45 67 89 AB CD EF }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexStringWithLowHighJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_low_high_jump {
	strings:
		$1 = { 01 23 [5-6] 45 56 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexStringWithLowJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_low_jump {
	strings:
		$1 = { 01 23 [5-] 45 56 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexStringWithUnrestrictedJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_unrestricted_jump {
	strings:
		$1 = { 01 23 [-] 45 56 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexStringWithConstantJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_constant_jump {
	strings:
		$1 = { 01 23 [5] 45 56 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexStringWithSimpleOrWorks) {
	prepareInput(
R"(
rule hex_string_with_simple_or_jump {
	strings:
		$1 = { 01 23 ( AB | CD ) 45 56 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_simple_or_jump", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 ( AB | CD ) 45 56 }", hexString->getText());
}

TEST_F(ParserTests,
HexStringWithMultibyteSimpleOrWorks) {
	prepareInput(
R"(
rule hex_string_with_multibyte_simple_or_jump {
	strings:
		$1 = { 01 23 ( AB CD EF | AA BB | EE | FF FF ) 45 56 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("hex_string_with_multibyte_simple_or_jump", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto hexString = strings[0];
	EXPECT_TRUE(hexString->isHex());
	EXPECT_EQ("$1", hexString->getIdentifier());
	EXPECT_EQ("{ 01 23 ( AB CD EF | AA BB | EE | FF FF ) 45 56 }", hexString->getText());
}

TEST_F(ParserTests,
HexStringWithNestedOrWorks) {
	prepareInput(
R"(
rule hex_string_with_nested_or {
	strings:
		$1 = { 01 23 ( AB ( EE | FF ( 11 | 22 ) FF | ( 11 22 | 33 ) ) | DD ) 45 56 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexStringWithOrAndJumpWorks) {
	prepareInput(
R"(
rule hex_string_with_or_and_jump {
	strings:
		$1 = { 01 23 ( AA DD | FF [5-7] FF ) 45 56 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexStringWithOrOnTheBeginningAndEnd) {
	prepareInput(
R"(
rule hex_string_with_or_on_the_beginning_and_end {
	strings:
		$1 = { ( 11 | 22 ) 33 44 ( 55 | 66 ) }
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
HexStringWithJumpAtBeginningForbidden) {
	prepareInput(
R"(
rule hex_string_with_jump_at_beginning {
	strings:
		$1 = { [5-6] 11 22 33 }
	condition:
		true
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.10: syntax error, unexpected LSQB, expecting LP or HEX_WILDCARD or HEX_NIBBLE", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
HexStringWithJumpAtEndForbidden) {
	prepareInput(
R"(
rule hex_string_with_jump_at_end {
	strings:
		$1 = { 11 22 33 [5-6] }
	condition:
		true
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.25: syntax error, unexpected RCB, expecting LP or LSQB or HEX_WILDCARD or HEX_NIBBLE", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
RegexpWithJustCharsWorks) {
	prepareInput(
R"(
rule regexp_with_just_chars {
	strings:
		$1 = /abcd/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("regexp_with_just_chars", rule->getName());
	EXPECT_EQ(Rule::Modifier::None, rule->getModifier());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto regexp = strings[0];
	EXPECT_TRUE(regexp->isRegexp());
	EXPECT_EQ("$1", regexp->getIdentifier());
	EXPECT_EQ("/abcd/", regexp->getText());
}

TEST_F(ParserTests,
RegexpLimitedToWholeLineWorks) {
	prepareInput(
R"(
rule regexp_limited_to_whole_line {
	strings:
		$1 = /^abcd$/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithPredefinedClassesWorks) {
	prepareInput(
R"(
rule regexp_with_predefined_classes {
	strings:
		$1 = /\w\W\s\S\d\D\babc\B/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithCustomClassWorks) {
	prepareInput(
R"(
rule regexp_with_custom_class {
	strings:
		$1 = /abc[xyz]def/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithCustomNegativeClassWorks) {
	prepareInput(
R"(
rule regexp_with_custom_negative_class {
	strings:
		$1 = /abc[^xyz]def/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithIterationWorks) {
	prepareInput(
R"(
rule regexp_with_iteration {
	strings:
		$1 = /ab*c/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithPositiveIterationWorks) {
	prepareInput(
R"(
rule regexp_with_positive_iteration {
	strings:
		$1 = /ab+c/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithOptionalWorks) {
	prepareInput(
R"(
rule regexp_with_optional {
	strings:
		$1 = /ab?c/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithRangesWorks) {
	prepareInput(
R"(
rule regexp_with_ranges {
	strings:
		$1 = /a{5}b{2,3}c{4,}d{,5}/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithGreedyOperatorsWorks) {
	prepareInput(
R"(
rule regexp_with_greedy_operators {
	strings:
		$1 = /a*?b+?c??d{5,6}?/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithGroupsWorks) {
	prepareInput(
R"(
rule regexp_with_groups {
	strings:
		$1 = /ab(cd(ef)gh(i))/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithOrWorks) {
	prepareInput(
R"(
rule regexp_with_or {
	strings:
		$1 = /(abc|def|xyz)/
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithModifiersWorks) {
	prepareInput(
R"(
rule regexp_with_modifiers {
	strings:
		$1 = /(abc|def|xyz)/ wide
		$2 = /(abc|def|xyz)/ nocase fullword
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
RegexpWithUndefinedRangeForbidden) {
	prepareInput(
R"(
rule regexp_with_undefined_range {
	strings:
		$1 = /ab{,}/
	condition:
		true
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.14: Range in regular expression does not have defined lower bound nor higher bound", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
RegexpWithInvalidRangeForbidden) {
	prepareInput(
R"(
rule regexp_with_invalid_range {
	strings:
		$1 = /ab{6,5}/
	condition:
		true
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.16: Range in regular expression has greater lower bound than higher bound", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
GlobalRuleModifierWorks) {
	prepareInput(
R"(
global rule global_rule {
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("global_rule", rule->getName());
	EXPECT_EQ(Rule::Modifier::Global, rule->getModifier());
	EXPECT_TRUE(rule->isGlobal());
}

TEST_F(ParserTests,
PrivateRuleModifierWorks) {
	prepareInput(
R"(
private rule private_rule {
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("private_rule", rule->getName());
	EXPECT_EQ(Rule::Modifier::Private, rule->getModifier());
	EXPECT_TRUE(rule->isPrivate());
}

TEST_F(ParserTests,
ImportWorks) {
	prepareInput(
R"(
import "pe"

rule dummy_rule {
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	EXPECT_EQ(1u, driver.getParsedFile().getRules().size());
	ASSERT_EQ(1u, driver.getParsedFile().getImports().size());
	EXPECT_EQ("pe", driver.getParsedFile().getImports()[0]->getName());
}

TEST_F(ParserTests,
ImportOfUnrecognizedModuleForbidden) {
	prepareInput(
R"(
import "module"

rule dummy_rule {
	condition:
		true
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		ASSERT_EQ(0u, driver.getParsedFile().getImports().size());
		EXPECT_EQ("Error at 2.15: Unrecognized module 'module' imported", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
TrueConditionWorks) {
	prepareInput(
R"(
rule true_condition {
	condition:
		true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("true", rule->getCondition()->getText());
}

TEST_F(ParserTests,
FalseConditionWorks) {
	prepareInput(
R"(
rule false_condition {
	condition:
		false
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("false", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StringIdConditionWorks) {
	prepareInput(
R"(
rule string_id_condition {
	strings:
		$1 = "Hello World!"
	condition:
		$1
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$1", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StringAtEntryPointConditionWorks) {
	prepareInput(
R"(
rule string_at_entrypoint_condition {
	strings:
		$1 = "Hello World!"
	condition:
		$1 at entrypoint
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$1 at entrypoint", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StringInRangeConditionWorks) {
	prepareInput(
R"(
rule string_in_range_condition {
	strings:
		$1 = "Hello World!"
	condition:
		$1 in (10 .. 20)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("$1 in (10 .. 20)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
NotConditionWorks) {
	prepareInput(
R"(
rule not_condition {
	condition:
		not true
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("not true", rule->getCondition()->getText());
}

TEST_F(ParserTests,
AndConditionWorks) {
	prepareInput(
R"(
rule and_condition {
	condition:
		true and not false
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("true and not false", rule->getCondition()->getText());
}

TEST_F(ParserTests,
OrConditionWorks) {
	prepareInput(
R"(
rule and_condition {
	condition:
		true or not false
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("true or not false", rule->getCondition()->getText());
}

TEST_F(ParserTests,
RelationalConditionWorks) {
	prepareInput(
R"(
rule relational_condition {
	condition:
		filesize < 10 or filesize > 20 or filesize <= 10 or filesize >= 20 or filesize != 15 or filesize == 16
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("filesize < 10 or filesize > 20 or filesize <= 10 or filesize >= 20 or filesize != 15 or filesize == 16", rule->getCondition()->getText());
}

TEST_F(ParserTests,
ParenthesesConditionWorks) {
	prepareInput(
R"(
rule relational_condition {
	strings:
		$1 = "Hello World"
	condition:
		($1 at (entrypoint)) and (filesize > 100)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("($1 at (entrypoint)) and (filesize > 100)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
ArithmeticOpConditionWorks) {
	prepareInput(
R"(
rule arithmetic_op_condition {
	condition:
		(10 + 20 < 200 - 100) and (10 * 20 > 20 \ 10) and (10 % 2) and (-5)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((10 + 20 < 200 - 100) and (10 * 20 > 20 \ 10) and (10 % 2) and (-5))", rule->getCondition()->getText());
}

TEST_F(ParserTests,
BitwiseOpConditionWorks) {
	prepareInput(
R"(
rule bitwise_op_condition {
	condition:
		(3 & 2 == 2) and (7 ^ 7 == 0) and (3 | 4 == 7) and (~5) and (8 >> 2 == 2) and (1 << 3 == 8)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((3 & 2 == 2) and (7 ^ 7 == 0) and (3 | 4 == 7) and (~5) and (8 >> 2 == 2) and (1 << 3 == 8))", rule->getCondition()->getText());
}

TEST_F(ParserTests,
IntFunctionConditionWorks) {
	prepareInput(
R"(
rule int_function_condition {
	condition:
		int8(uint32(int32be(5))) == 64
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("int8(uint32(int32be(5))) == 64", rule->getCondition()->getText());
}

TEST_F(ParserTests,
DoubleInConditionWorks) {
	prepareInput(
R"(
rule double_in_condition {
	condition:
		1.23 + 4.56 > 10.5
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("1.23 + 4.56 > 10.5", rule->getCondition()->getText());
}

TEST_F(ParserTests,
ContainsInConditionWorks) {
	prepareInput(
R"(
rule contains_in_condition {
	condition:
		"Hello" contains "Hell"
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"("Hello" contains "Hell")", rule->getCondition()->getText());
}

TEST_F(ParserTests,
MatchesInConditionWorks) {
	prepareInput(
R"(
rule matches_in_condition {
	condition:
		"Hello" matches /^Hell.*$/
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"("Hello" matches /^Hell.*$/)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StringCountConditionWorks) {
	prepareInput(
R"(
rule string_count_condition {
	strings:
		$1 = "Hello World"
	condition:
		#1 == 5
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("#1 == 5", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StringOffsetConditionWorks) {
	prepareInput(
R"(
rule string_offset_condition {
	strings:
		$1 = "Hello World"
	condition:
		(@1 > 0) and (@1[0] > 100)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(@1 > 0) and (@1[0] > 100)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StringLengthConditionWorks) {
	prepareInput(
R"(
rule string_length_condition {
	strings:
		$1 = "Hello World"
	condition:
		(!1 > 0) and (!1[1] > 100)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(!1 > 0) and (!1[1] > 100)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
FunctionCallConditionWorks) {
	prepareInput(
R"(
import "pe"

rule function_call_condition {
	condition:
		(pe.is_dll()) and (pe.section_index(".text") == 0)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((pe.is_dll()) and (pe.section_index(".text") == 0))", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StructureAccessConditionWorks) {
	prepareInput(
R"(
import "pe"

rule structure_access_condition {
	condition:
		(pe.linker_version.major > 0) and (pe.linker_version.minor > 0)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(pe.linker_version.major > 0) and (pe.linker_version.minor > 0)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
ArrayAccessConditionWorks) {
	prepareInput(
R"(
import "pe"

rule array_access_condition {
	condition:
		(pe.number_of_sections > 0) and (pe.sections[0].name == ".text")
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"((pe.number_of_sections > 0) and (pe.sections[0].name == ".text"))", rule->getCondition()->getText());
}

TEST_F(ParserTests,
ForIntegerSetConditionWorks) {
	prepareInput(
R"(
rule for_integer_set_condition {
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		for all i in (1,2,3) : ( @a[i] + 10 == @b[i] )
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for all i in (1, 2, 3) : ( @a[i] + 10 == @b[i] )", rule->getCondition()->getText());
}

TEST_F(ParserTests,
ForStringSetConditionWorks) {
	prepareInput(
R"(
rule for_string_set_condition {
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		for any of ($a,$b) : ( $ at entrypoint )
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any of ($a, $b) : ( $ at entrypoint )", rule->getCondition()->getText());
}

TEST_F(ParserTests,
OfConditionWorks) {
	prepareInput(
R"(
rule of_condition {
	strings:
		$a = "dummy1"
		$b = "dummy2"
	condition:
		1 of ($a,$b)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("1 of ($a, $b)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StringsAndArithmeticOperationsForbidden) {
	prepareInput(
R"(
rule strings_and_arithmetic_operations {
	condition:
		10 + "hello"
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.1: operator '+' expects integer or float on the right-hand side", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
BoolAndArithmeticOperationsForbidden) {
	prepareInput(
R"(
rule bool_and_arithmetic_operations {
	condition:
		10 + true
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 4.8-11: syntax error, unexpected BOOL_TRUE", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
ContainsAndNonStringForbidden) {
	prepareInput(
R"(
rule contains_and_non_string {
	condition:
		"abc" contains 5
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 5.1: operator 'contains' expects string on the right-hand side of the expression", err.getErrorMessage());
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

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 7.1: Reference to undefined string '$2'", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
StringWildcardConditionWorks) {
	prepareInput(
R"(
rule string_wildcard_condition {
	strings:
		$aaa = "dummy1"
		$aab = "dummy2"
		$bbb = "dummy3"
	condition:
		for any of ($aa*, $bbb) : ( $ )
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("for any of ($aa*, $bbb) : ( $ )", rule->getCondition()->getText());
}

TEST_F(ParserTests,
StringWildcardConditionWithNoMatchingStringForbidden) {
	prepareInput(
R"(
rule string_wildcard_condition_with_no_matching_string {
	strings:
		$aaa = "dummy1"
		$aab = "dummy2"
		$bbb = "dummy3"
	condition:
		for any of ($c*) : ( $ )
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 8.15-17: No string matched with wildcard '$c*'", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
SameVariableInNestedForLoopsForbidden) {
	prepareInput(
R"(
rule same_variable_in_nested_for_loops {
	strings:
		$1 = "hello"
	condition:
		for all i in (1..5) : ( for any i in (10 .. 15) : ( $1 at i ) )
}
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 6.35: Redefinition of identifier 'i'", err.getErrorMessage());
	}
}

TEST_F(ParserTests,
CuckooModuleWorks) {
	prepareInput(
R"(
import "cuckoo"

rule cuckoo_module {
	strings:
		$some_string = { 01 02 03 04 05 05 }
	condition:
		$some_string and cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"($some_string and cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/))", rule->getCondition()->getText());
}

TEST_F(ParserTests,
DotnetModuleWorks) {
	prepareInput(
R"(
import "dotnet"

rule dotnet_module {
	condition:
		dotnet.assembly.version.major > 0 and dotnet.assembly.version.minor > 0
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("dotnet.assembly.version.major > 0 and dotnet.assembly.version.minor > 0", rule->getCondition()->getText());
}

TEST_F(ParserTests,
ElfModuleWorks) {
	prepareInput(
R"(
import "elf"

rule elf_module {
	condition:
		elf.type == elf.ET_EXEC and elf.sections[0].type == elf.SHT_NULL
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("elf.type == elf.ET_EXEC and elf.sections[0].type == elf.SHT_NULL", rule->getCondition()->getText());
}

TEST_F(ParserTests,
HashModuleWorks) {
	prepareInput(
R"(
import "hash"

rule hash_module {
	condition:
		hash.md5("dummy") == "275876e34cf609db118f3d84b799a790"
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(hash.md5("dummy") == "275876e34cf609db118f3d84b799a790")", rule->getCondition()->getText());
}

TEST_F(ParserTests,
MagicModuleWorks) {
	prepareInput(
R"(
import "magic"

rule magic_module {
	condition:
		magic.type() contains "PDF"
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(magic.type() contains "PDF")", rule->getCondition()->getText());
}

TEST_F(ParserTests,
MathModuleWorks) {
	prepareInput(
R"(
import "math"

rule math_module {
	condition:
		math.entropy("dummy") > 7
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(math.entropy("dummy") > 7)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
PeModuleWorks) {
	prepareInput(
R"(
import "pe"

rule pe_module {
	condition:
		pe.exports("ExitProcess") and pe.characteristics & pe.DLL
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(pe.exports("ExitProcess") and pe.characteristics & pe.DLL)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
TransformationToTextWorks) {
	prepareInput(
R"(
import "pe"

/**
 * Random block comment
 */
rule rule_1 : Tag1 Tag2 {
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { ab cd ef }
		$3 = /ab*c/
	condition:
		pe.exports("ExitProcess") and for any of them : ( $ at pe.entry_point )
}

import "elf"

// Random one-line comment
rule rule_2 {
	meta:
		valid = true
	strings:
		$abc = "no case full word" nocase fullword
	condition:
		elf.type == elf.ET_EXEC
		and
		$abc at elf.entry_point
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
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
}

TEST_F(ParserTests,
KbMbIntegerMultipliersWorks) {
	prepareInput(
R"(
rule kb_mb_integer_multipliers {
	condition:
		(1KB <= filesize) and (filesize <= 1MB)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("(1KB <= filesize) and (filesize <= 1MB)", rule->getCondition()->getText());
}

TEST_F(ParserTests,
ReferncingRuleFromOtherRuleWorks) {
	prepareInput(
R"(
rule rule_1 {
	condition:
		filesize > 100KB
}

rule rule_2 {
	condition:
		rule_1 and (filesize < 10MB)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());

	const auto& rule1 = driver.getParsedFile().getRules()[0];
	EXPECT_EQ("filesize > 100KB", rule1->getCondition()->getText());

	const auto& rule2 = driver.getParsedFile().getRules()[1];
	EXPECT_EQ("rule_1 and (filesize < 10MB)", rule2->getCondition()->getText());
}

TEST_F(ParserTests,
RegexpWithSuffixModifierWorks) {
	prepareInput(
R"(
import "cuckoo"

rule regexp_with_suffix_modifier {
	strings:
		$some_string = { 01 02 03 04 05 05 }
	condition:
		$some_string and cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/is)
}
)");

	ParserDriver driver(input);

	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"($some_string and cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/is))", rule->getCondition()->getText());
}

TEST_F(ParserTests,
GlobalVariablesWorks) {
	prepareInput(
R"(rule rule_with_global_variables {
	condition:
		new_file and positives > 10 and signatures matches /Trojan\.Generic.*/ and file_type contains "pe"
}
)");

	ParserDriver driver(input);
	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];
	EXPECT_EQ(R"(new_file and positives > 10 and signatures matches /Trojan\.Generic.*/ and file_type contains "pe")", rule->getCondition()->getText());
}

TEST_F(ParserTests,
LengthOfHexStringWorks) {
	prepareInput(
R"(rule rule_with_some_hex_string {
	strings:
		$hex_string = { 11 ?? 22 [4-5] ( 66 | 77 ) 88 }
	condition:
		$hex_string
}
)");

	ParserDriver driver(input);
	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto string = strings[0];
	ASSERT_TRUE(string->isHex());

	EXPECT_EQ(12u, static_cast<const HexString*>(string)->getLength());
}

TEST_F(ParserTests,
NibbleGetterWorks) {
	prepareInput(
R"(rule rule_with_some_hex_string {
	strings:
		$hex_string = { 9F }
	condition:
		$hex_string
}
)");

	ParserDriver driver(input);
	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto string = strings[0];
	ASSERT_TRUE(string->isHex());

	const auto units = static_cast<const HexString*>(string)->getUnits();
	EXPECT_EQ(0x9, std::static_pointer_cast<HexStringNibble>(units[0])->getValue());
	EXPECT_EQ(0xF, std::static_pointer_cast<HexStringNibble>(units[1])->getValue());
}

TEST_F(ParserTests,
EscapedSequencesWorks) {
	prepareInput(
R"(import"pe"

rule rule_with_escaped_double_quotes_works {
	meta:
		str_meta = "Here are \"\t\n\\\x01\xff"
	strings:
		$str = "Another \"\t\n\\\x01\xff"
	condition:
		pe.rich_signature.clear_data == "DanS\"\t\n\\\x01\xff"
}"
)");

	ParserDriver driver(input);
	EXPECT_TRUE(driver.parse());
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());

	const auto& rule = driver.getParsedFile().getRules()[0];

	auto strMeta = rule->getMetaWithName("str_meta");
	ASSERT_NE(strMeta, nullptr);
	auto expected = R"("Here are \"\t\n\\\x01\xff")";
	EXPECT_EQ(expected, strMeta->getValue().getText());
	EXPECT_EQ("Here are \"\t\n\\\x01\xff", strMeta->getValue().getPureText());

	auto strings = rule->getStrings();
	ASSERT_EQ(1u, strings.size());

	auto str = strings[0];
	ASSERT_TRUE(str->isPlain());
	expected = R"("Another \"\t\n\\\x01\xff")";
	EXPECT_EQ(expected, str->getText());
	EXPECT_EQ("Another \"\t\n\\\x01\xff", str->getPureText());

	expected = R"(pe.rich_signature.clear_data == "DanS\"\t\n\\\x01\xff")";
	EXPECT_EQ(expected, rule->getCondition()->getText());
}

TEST_F(ParserTests,
InvalidEscapeSequence) {
	prepareInput(
R"(rule rule_with_invalid_escape_sequence {
	strings:
		$str = "\n\r"
	condition:
		$str
}"
)");

	ParserDriver driver(input);

	try
	{
		driver.parse();
		FAIL() << "Parser did not throw an exception.";
	}
	catch (const ParserError& err)
	{
		EXPECT_EQ(0u, driver.getParsedFile().getRules().size());
		EXPECT_EQ("Error at 3.13-14: Unknown escape sequence '\\r'", err.getErrorMessage());
	}
}

}
}
