/**
* @file tests/visitor_tests.cpp
* @brief Tests for the YARA representation.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "yaramod/builder/yara_expression_builder.h"
#include "yaramod/parser/parser_driver.h"
#include "yaramod/utils/modifying_visitor.h"

using namespace ::testing;

namespace yaramod {
namespace tests {

class VisitorTests : public Test
{
public:
	VisitorTests() : driver() {}

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

TEST_F(VisitorTests,
RegexpModifyingVisitorInpactOnTokenStream) {
	class TestModifyingVisitor : public yaramod::ModifyingVisitor
	{
	public:
		void process_rule(const std::shared_ptr<Rule>& rule)
		{
			auto modified = modify(rule->getCondition());
			rule->setCondition(std::move(modified));
		}
		virtual yaramod::VisitResult visit(RegexpExpression* expr) override
		{
			return yaramod::regexp("abc", "i").get();
		}
	};
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
    condition:
        cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/)
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	TestModifyingVisitor visitor;
	visitor.process_rule(rule);

	EXPECT_EQ("rule_name", rule->getName());
	EXPECT_EQ("cuckoo.network.http_request(/abc/i)", rule->getCondition()->getText());

	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		cuckoo.network.http_request(/abc/i)
}
)";
	EXPECT_EQ(expected, yara_file.getTextFormatted());
}

TEST_F(VisitorTests,
BoolModifyingVisitorInpactOnTokenStream1) {
	class TestModifyingVisitor : public yaramod::ModifyingVisitor
	{
	public:
		void process_rule(const std::shared_ptr<Rule>& rule) {
			auto modified = modify(rule->getCondition());
			rule->setCondition(std::move(modified));
		}
		virtual yaramod::VisitResult visit(BoolLiteralExpression* expr) override
		{
			return yaramod::boolVal(false).get();
		}
	};
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
    condition:
        true
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	TestModifyingVisitor visitor;
	visitor.process_rule(rule);

	EXPECT_EQ("rule_name", rule->getName());

	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		false
}
)";
	EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
	EXPECT_EQ("false", rule->getCondition()->getText());
}
TEST_F(VisitorTests,
BoolModifyingVisitorInpactOnTokenStream2) {
	class TestModifyingVisitor : public yaramod::ModifyingVisitor
	{
	public:
		void process_rule(const std::shared_ptr<Rule>& rule) {
			auto modified = modify(rule->getCondition());
			rule->setCondition(std::move(modified));
		}
		virtual yaramod::VisitResult visit(BoolLiteralExpression* expr) override
		{
			return yaramod::boolVal(false).get();
		}
	};
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
    condition:
        true and true
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	TestModifyingVisitor visitor;
	visitor.process_rule(rule);

	EXPECT_EQ("rule_name", rule->getName());

	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		false and
		false
}
)";
	EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
	EXPECT_EQ("false and false", rule->getCondition()->getText());
}

TEST_F(VisitorTests,
IntLiteralModifyingVisitorInpactOnTokenStream) {
	class TestModifyingVisitor : public yaramod::ModifyingVisitor
	{
	public:
		void process_rule(const std::shared_ptr<Rule>& rule) {
			auto modified = modify(rule->getCondition());
			rule->setCondition(std::move(modified));
		}
		virtual yaramod::VisitResult visit(IntLiteralExpression* expr) override
		{
			return yaramod::intVal(111).get();
		}
	};
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
	condition:
		10
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	TestModifyingVisitor visitor;
	visitor.process_rule(rule);

	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		111
}
)";
	EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
	EXPECT_EQ("111", rule->getCondition()->getText());
}

}
}
