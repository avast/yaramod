/**
* @file tests/visitor_tests.cpp
* @brief Tests for the YARA representation.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <clocale>

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
StringExpressionVisitorInpactOnTokenStream) {
	class StringExpressionUpper : public yaramod::ModifyingVisitor
	{
	public:
		void process(const YaraFile& file)
		{
			for (const std::shared_ptr<Rule>& rule : file.getRules())
			{
				auto modified = modify(rule->getCondition());
				rule->setCondition(std::move(modified));
			}
		}
		virtual yaramod::VisitResult visit(StringExpression* expr) override
		{
			std::string id = expr->getId();
			std::string upper;
			for (char c : id)
				upper += std::toupper(c);
			expr->setId(upper);
			return {};
		}
	};
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
	strings:
		$string1 = "string 1"
	condition:
		$string1 and !string1 == 1
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();

	StringExpressionUpper visitor;
	visitor.process(yara_file);

	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	EXPECT_EQ("rule_name", rule->getName());
	EXPECT_EQ("$STRING1 and !STRING1 == 1", rule->getCondition()->getText());

	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	strings:
		$STRING1 = "string 1"
	condition:
		$STRING1 and
		!STRING1 == 1
}
)";
	EXPECT_EQ(expected, yara_file.getTextFormatted());
}

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
			auto new_condition = regexp("abc", "i").get();
			expr->exchangeTokens(new_condition.get());
			return new_condition;
		}
	};
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
    condition:
        true and cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/)
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	TestModifyingVisitor visitor;
	visitor.process_rule(rule);

	EXPECT_EQ("rule_name", rule->getName());
	EXPECT_EQ("true and cuckoo.network.http_request(/abc/i)", rule->getCondition()->getText());

	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		true and
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
			auto new_condition = boolVal(false).get();
			expr->exchangeTokens(new_condition.get());
			return new_condition;
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
			auto new_condition = boolVal(false).get();
			expr->exchangeTokens(new_condition.get());
			return new_condition;
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
			auto new_condition = yaramod::intVal(111).get();
			expr->exchangeTokens(new_condition.get());
			return new_condition;
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

class CuckooFunctionReplacer : public ModifyingVisitor
{
public:
	CuckooFunctionReplacer(YaraFile* yaraFile)
		: _yaraFile(yaraFile)
		, _needsToBeRemoved(false)
		, _fileAccessSymbol(nullptr)
		, _keyAccessSymbol(nullptr)
	{
	}
	bool preFileTransform()
	{
		auto cuckooStruct = std::static_pointer_cast<yaramod::StructureSymbol>(_yaraFile->findSymbol("cuckoo"));
		if (cuckooStruct == nullptr)
			return false;

		auto filesystemStruct = std::static_pointer_cast<yaramod::StructureSymbol>(cuckooStruct->getAttribute("filesystem").value());
		_fileAccessSymbol = filesystemStruct->getAttribute("file_access").value();

		auto registryStruct = std::static_pointer_cast<yaramod::StructureSymbol>(cuckooStruct->getAttribute("registry").value());
		_keyAccessSymbol = registryStruct->getAttribute("key_access").value();

		return true;
	}
	void postRuleTransform(const std::shared_ptr<Rule>& rule)
	{
		if (_needsToBeRemoved)
		{
			auto new_condition = boolVal(false).get();
			rule->getCondition()->exchangeTokens(new_condition.get());
			rule->setCondition(new_condition);
		}
		_needsToBeRemoved = false;
	}
	void process_rule(const std::shared_ptr<Rule>& rule)
	{
		preFileTransform();
		auto modified = modify(rule->getCondition());
		if (!_needsToBeRemoved)
			rule->setCondition(std::move(modified));
		postRuleTransform(rule);
	}
	virtual yaramod::VisitResult visit(IntLiteralExpression* expr) override
	{
		auto new_condition = yaramod::intVal(111).get();
		expr->exchangeTokens(new_condition.get());
		return new_condition;
	}
	virtual VisitResult visit(NotExpression* expr) override
	{
		expr->getOperand()->accept(this);

		if (_needsToBeRemoved)
		{
			auto new_condition = boolVal(false).get();
			expr->getOperand()->exchangeTokens(new_condition.get());
			expr->setOperand(new_condition);
		}
		_needsToBeRemoved = false;
		return {};

	}
	virtual VisitResult visit(AndExpression* expr) override
	{
		_handleBinaryExpression(expr);
		return {};
	}
	virtual VisitResult visit(OrExpression* expr) override
	{
		_handleBinaryExpression(expr);
		return {};
	}
	virtual VisitResult visit(FunctionCallExpression* expr) override
	{
		auto functionName = expr->getFunction()->getText();
		if (isFunctionInBlacklist(functionName, avastOnlyFunctionsRemove))
			_needsToBeRemoved = true;
		return expr;
	}
	virtual VisitResult visit(ParenthesesExpression* expr) override
	{
		expr->getEnclosedExpression()->accept(this);

		if (_needsToBeRemoved)
		{
			auto new_condition = boolVal(false).get();
			expr->getEnclosedExpression()->exchangeTokens(new_condition.get());
			expr->setEnclosedExpression(new_condition);
		}
		_needsToBeRemoved = false;
		return {};
	}
private:
	bool isFunctionInBlacklist(const std::string& functionName, const std::unordered_set<std::string>& blacklist)
	{
		return blacklist.find(functionName) != blacklist.end();
	}

	template <typename BinaryExp>
	void _handleBinaryExpression(BinaryExp* expr)
	{
		expr->getLeftOperand()->accept(this);
		bool leftNeedsToBeRemoved = _needsToBeRemoved;
		_needsToBeRemoved = false;

		expr->getRightOperand()->accept(this);
		bool rightNeedsToBeRemoved = _needsToBeRemoved;
		_needsToBeRemoved = false;

		if (leftNeedsToBeRemoved && rightNeedsToBeRemoved)
		{
			_needsToBeRemoved = true;
		}
		else if (leftNeedsToBeRemoved)
		{
			auto new_condition = boolVal(false).get();
			expr->getLeftOperand()->exchangeTokens(new_condition.get());
			expr->setLeftOperand(new_condition);
		}
		else if (rightNeedsToBeRemoved)
		{
			auto new_condition = boolVal(false).get();
			expr->getRightOperand()->exchangeTokens(new_condition.get());
			expr->setRightOperand(new_condition);
		}
	}

	YaraFile* _yaraFile;
	bool _needsToBeRemoved;
	std::shared_ptr<Symbol> _fileAccessSymbol;
	std::shared_ptr<Symbol> _keyAccessSymbol;

	const std::unordered_set<std::string> avastOnlyFunctionsRemove =
	{
		"cuckoo.network.http_request_body"
	};
};

TEST_F(VisitorTests,
CuckooFunctionReplacerBoolLiteralExpression) {
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
	condition:
		false
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	CuckooFunctionReplacer cuckooReplacer(&yara_file);
	cuckooReplacer.process_rule(rule);

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
CuckooFunctionReplacerCuckooSyncEvent) {
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
	condition:
		cuckoo.network.http_request_body(/http:\/\/someone\.doingevil\.com/)
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	CuckooFunctionReplacer cuckooReplacer(&yara_file);
	cuckooReplacer.process_rule(rule);

	ASSERT_EQ(R"(import "cuckoo"

rule rule_name {
	condition:
		false
})", yara_file.getText());
	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		false
}
)";
    EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("false", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
}

TEST_F(VisitorTests,
CuckooFunctionReplacerOrExpression1) {
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
	condition:
		cuckoo.network.http_request_body(/a/) or
		cuckoo.network.http_request_body(/b/)
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	CuckooFunctionReplacer cuckooReplacer(&yara_file);
	cuckooReplacer.process_rule(rule);

	ASSERT_EQ(R"(import "cuckoo"

rule rule_name {
	condition:
		false
})", yara_file.getText());
	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		false
}
)";
    EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("false", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
}

TEST_F(VisitorTests,
CuckooFunctionReplacerOrExpression2) {
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
	condition:
		entrypoint == 0 or
		cuckoo.network.http_request_body(/b/)
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	CuckooFunctionReplacer cuckooReplacer(&yara_file);
	cuckooReplacer.process_rule(rule);

	ASSERT_EQ(R"(import "cuckoo"

rule rule_name {
	condition:
		entrypoint == 111 or false
})", yara_file.getText());
	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		entrypoint == 111 or
		false
}
)";
    EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("entrypoint == 111 or false", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
}

TEST_F(VisitorTests,
CuckooFunctionReplacerOrExpression3) {
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
	condition:
	entrypoint == 0 or
	(
		cuckoo.network.http_request_body(/a/) or
		cuckoo.network.http_request_body(/b/)
	)
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	CuckooFunctionReplacer cuckooReplacer(&yara_file);
	cuckooReplacer.process_rule(rule);

	ASSERT_EQ(R"(import "cuckoo"

rule rule_name {
	condition:
		entrypoint == 111 or (false)
})", yara_file.getText());
	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		entrypoint == 111 or
		(
			false
		)
}
)";
    EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("entrypoint == 111 or (false)", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
}

TEST_F(VisitorTests,
CuckooFunctionReplacerOrExpression4) {
	prepareInput(
R"(
import "cuckoo"
rule rule_name {
	condition:
	cuckoo.network.http_request_body(/a/) or
	(
		filesize > 12 and
		true or
		cuckoo.network.http_request_body(/b/)
	)
}
)");
	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	CuckooFunctionReplacer cuckooReplacer(&yara_file);
	cuckooReplacer.process_rule(rule);

	ASSERT_EQ(R"(import "cuckoo"

rule rule_name {
	condition:
		false or (filesize > 111 and true or false)
})", yara_file.getText());
	std::string expected = R"(
import "cuckoo"

rule rule_name
{
	condition:
		false or
		(
			filesize > 111 and
			true or
			false
		)
}
)";
    EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("false or (filesize > 111 and true or false)", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
}

TEST_F(VisitorTests,
CuckooFunctionReplacerAndExpression1) {
	prepareInput(
R"(
import "pe"
import "elf"
import "cuckoo"

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
		cuckoo.network.http_request_body(/a/)
		and
		for any of them : ( $ at pe.entry_point )
}

// Random one-line comment
rule rule_2
{
	meta:
		valid = true
	strings:
		$abc = "no case full word" nocase fullword
	condition:
		elf.type == elf.ET_EXEC and $abc at elf.entry_point and cuckoo.network.http_request_body(/b/) and filesize == 10
}
)");

	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(2u, yara_file.getRules().size());
	const auto& rule1 = yara_file.getRules()[0];
	const auto& rule2 = yara_file.getRules()[1];

	CuckooFunctionReplacer cuckooReplacer(&yara_file);
	cuckooReplacer.process_rule(rule1);
	cuckooReplacer.process_rule(rule2);

	EXPECT_EQ(
R"(import "pe"
import "elf"
import "cuckoo"

rule rule_1 : Tag1 Tag2 {
	meta:
		info = "meta info"
		version = 2
	strings:
		$1 = "plain string" wide
		$2 = { AB CD EF }
		$3 = /ab*c/
	condition:
		pe.exports("ExitProcess") and false and for any of them : ( $ at pe.entry_point )
}

rule rule_2 {
	meta:
		valid = true
	strings:
		$abc = "no case full word" nocase fullword
	condition:
		elf.type == elf.ET_EXEC and $abc at elf.entry_point and false and filesize == 111
})", yara_file.getText());

	std::string expected = R"(
import "pe"
import "elf"
import "cuckoo"

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
		false and
		for any of them : ( $ at pe.entry_point )
}

// Random one-line comment
rule rule_2
{
	meta:
		valid = true
	strings:
		$abc = "no case full word" nocase fullword
	condition:
		elf.type == elf.ET_EXEC and
		$abc at elf.entry_point and
		false and
		filesize == 111
}
)";

	EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("pe.exports(\"ExitProcess\") and false and for any of them : ( $ at pe.entry_point )", rule1->getCondition()->getText());
	EXPECT_EQ(expected, rule1->getCondition()->getTokenStream()->getText());
	EXPECT_EQ("elf.type == elf.ET_EXEC and $abc at elf.entry_point and false and filesize == 111", rule2->getCondition()->getText());
	EXPECT_EQ(expected, rule2->getCondition()->getTokenStream()->getText());
}

class AndExpressionSwitcher : public ModifyingVisitor
{
public:
	AndExpressionSwitcher(YaraFile* yaraFile)
		: _yaraFile(yaraFile)
	{
	}

	void process_rule(const std::shared_ptr<Rule>& rule)
	{
		auto modified = modify(rule->getCondition());
		rule->setCondition(std::move(modified));
	}
	virtual VisitResult visit(AndExpression* expr) override
	{
		_handleBinaryExpression(expr);
		return {};
	}

private:
	template <typename BinaryExp>
	void _handleBinaryExpression(BinaryExp* expr)
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		std::shared_ptr<Expression> tmp_condition = expr->getLeftOperand();
		expr->getLeftOperand()->exchangeTokens(expr->getRightOperand().get());
		expr->setLeftOperand(expr->getRightOperand());
		expr->setRightOperand(tmp_condition);
	}

	YaraFile* _yaraFile;
};

TEST_F(VisitorTests,
AndExpressionSwitcherAndExpression1) {
	prepareInput(
R"(
rule rule_1
{
	strings:
		$1 = "s1" wide
		$2 = "s2"
	condition:
		any of them and
		$2
}
)");

	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	AndExpressionSwitcher visitor(&yara_file);
	visitor.process_rule(rule);

	EXPECT_EQ(
R"(rule rule_1 {
	strings:
		$1 = "s1" wide
		$2 = "s2"
	condition:
		$2 and any of them
})", yara_file.getText());

	std::string expected = R"(
rule rule_1
{
	strings:
		$1 = "s1" wide
		$2 = "s2"
	condition:
		$2 and
		any of them
}
)";

	EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("$2 and any of them", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
}

TEST_F(VisitorTests,
AndExpressionSwitcherAndExpression2) {
	prepareInput(
R"(
rule rule_1
{
	strings:
		$1 = "s1" wide
		$2 = "s2"
		$3 = "s3"
		$4 = "s4"
		$5 = "s5" fullword
		$6 = "s6"
	condition:
		(
			$1 and
			$2 and
			$3 and
			true and
			$4 and
			$5 and
			$6
		) or
		false
}
)");

	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	AndExpressionSwitcher visitor(&yara_file);
	visitor.process_rule(rule);

	EXPECT_EQ(
R"(rule rule_1 {
	strings:
		$1 = "s1" wide
		$2 = "s2"
		$3 = "s3"
		$4 = "s4"
		$5 = "s5" fullword
		$6 = "s6"
	condition:
		($6 and $5 and $4 and true and $3 and $2 and $1) or false
})", yara_file.getText());

	std::string expected = R"(
rule rule_1
{
	strings:
		$1 = "s1" wide
		$2 = "s2"
		$3 = "s3"
		$4 = "s4"
		$5 = "s5" fullword
		$6 = "s6"
	condition:
		(
			$6 and
			$5 and
			$4 and
			true and
			$3 and
			$2 and
			$1
		) or
		false
}
)";

	EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("($6 and $5 and $4 and true and $3 and $2 and $1) or false", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
}

class OrExpressionSwitcher : public ModifyingVisitor
{
public:
	OrExpressionSwitcher(YaraFile* yaraFile)
		: _yaraFile(yaraFile)
	{
	}

	void process_rule(const std::shared_ptr<Rule>& rule)
	{
		auto modified = modify(rule->getCondition());
		rule->setCondition(std::move(modified));
	}
	virtual VisitResult visit(OrExpression* expr) override
	{
		auto output = _handleBinaryExpression(expr);
		return output;
	}

private:

	template <typename BinaryExp>
	std::shared_ptr<Expression> _handleBinaryExpression(BinaryExp* expr)
	{
		//save old TS and expression start-end within it
		TokenStreamContext context(expr);
		auto leftResult = expr->getLeftOperand()->accept(this);
		if (resultIsModified(leftResult))
			expr->setLeftOperand(std::get<std::shared_ptr<Expression>>(leftResult));
		auto rightResult = expr->getRightOperand()->accept(this);
		if (resultIsModified(rightResult))
			expr->setRightOperand(std::get<std::shared_ptr<Expression>>(rightResult));
		//create new expression
		auto output = disjunction({YaraExpressionBuilder(expr->getRightOperand()), YaraExpressionBuilder(expr->getLeftOperand())}).get();

		cleanUpTokenStreams(context, output.get());
		return output;
	}
	YaraFile* _yaraFile;
};

TEST_F(VisitorTests,
OrExpressionSwitcherOrExpression1) {
	prepareInput(
R"(
rule rule_1
{
	strings:
		$1 = "s1" wide
		$2 = "s2"
	condition:
		true and
		(
			any of them or
			$2
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	OrExpressionSwitcher visitor(&yara_file);
	visitor.process_rule(rule);

	EXPECT_EQ(
R"(rule rule_1 {
	strings:
		$1 = "s1" wide
		$2 = "s2"
	condition:
		true and ($2 or any of them)
})", yara_file.getText());

	std::string expected = R"(
rule rule_1
{
	strings:
		$1 = "s1" wide
		$2 = "s2"
	condition:
		true and
		(
			$2 or
			any of them
		)
}
)";

	EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("true and ($2 or any of them)", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
	EXPECT_EQ(rule->getCondition()->getFirstTokenIt()->getPureText(), "true");
	EXPECT_EQ(rule->getCondition()->getLastTokenIt()->getPureText(), ")");
	EXPECT_TRUE(rule->getCondition()->isBool());
	auto expAnd = std::static_pointer_cast<const AndExpression>(rule->getCondition());
	auto expPar = std::static_pointer_cast<const ParenthesesExpression>(expAnd->getRightOperand());
	auto expOr = std::static_pointer_cast<const OrExpression>(expPar->getEnclosedExpression());
	auto expLeft = std::static_pointer_cast<const StringExpression>(expOr->getLeftOperand());
	auto expRight = std::static_pointer_cast<const OfExpression>(expOr->getRightOperand());
	EXPECT_EQ(expOr->getOperator()->getPureText(), "or");
	EXPECT_EQ(expLeft->getFirstTokenIt()->getPureText(), "$2");
	EXPECT_EQ(expLeft->getLastTokenIt()->getPureText(), "$2");
	EXPECT_EQ(expRight->getFirstTokenIt()->getPureText(), "any");
	EXPECT_EQ(expRight->getLastTokenIt()->getPureText(), "them");
}

TEST_F(VisitorTests,
OrExpressionSwitcherOrExpression2) {
	prepareInput(
R"(
rule rule_1
{
	strings:
		$1 = "s1" wide
		$2 = "s2"
		$3 = "s3"
	condition:
		$1 or
		$2 or
		$3
}
)");

	EXPECT_TRUE(driver.parse(input));
	auto yara_file = driver.getParsedFile();
	ASSERT_EQ(1u, yara_file.getRules().size());
	const auto& rule = yara_file.getRules()[0];

	OrExpressionSwitcher visitor(&yara_file);
	visitor.process_rule(rule);

	EXPECT_EQ(
R"(rule rule_1 {
	strings:
		$1 = "s1" wide
		$2 = "s2"
		$3 = "s3"
	condition:
		$3 or $2 or $1
})", yara_file.getText());

	std::string expected = R"(
rule rule_1
{
	strings:
		$1 = "s1" wide
		$2 = "s2"
		$3 = "s3"
	condition:
		$3 or
		$2 or
		$1
}
)";

	EXPECT_EQ(expected, yara_file.getTextFormatted());
	EXPECT_EQ("$3 or $2 or $1", rule->getCondition()->getText());
	EXPECT_EQ(expected, rule->getCondition()->getTokenStream()->getText());
}

}
}
