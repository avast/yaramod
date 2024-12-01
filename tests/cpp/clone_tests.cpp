#include <gtest/gtest.h>

#include "yaramod/parser/parser_driver.h"
#include "yaramod/types/expressions.h"


using namespace ::testing;

namespace yaramod {
namespace tests {

class CloneTests : public Test
{
public:
	CloneTests() : driver(), new_ts(std::make_shared<TokenStream>()) {}

	void prepareInput(const std::string& inputText)
	{
		input.str(std::string());
		input.clear();
		input << inputText;
		input_text = inputText;
	}

	testing::AssertionResult expectTokensPred(const char*, std::initializer_list<std::string> tokens)
	{
		if (new_ts->size() == tokens.size())
		{
			auto actual = new_ts->begin();
			auto expected = tokens.begin();

			for (size_t i = 0; i < tokens.size(); ++i, ++actual, ++expected)
			{
				if (actual->getPureText() != *expected)
				{
					std::ostringstream ss;
					for (auto itr = new_ts->begin(); itr != new_ts->end(); ++itr)
						ss << (itr == new_ts->begin() ? "" : ", ") << itr->getPureText();

					return testing::AssertionFailure() << "Tokens on position " << i << " are not equal\n"
						<< "Actual   : " << actual->getPureText() << "\n"
						<< "Expected : " << *expected << "\n"
						<< "\n"
						<< "Token Stream : " << ss.str();
				}
			}
		}
		else
		{
			std::ostringstream ss;
			for (auto itr = new_ts->begin(); itr != new_ts->end(); ++itr)
				ss << (itr == new_ts->begin() ? "" : ", ") << itr->getPureText();

			return testing::AssertionFailure() << "Expected token stream and actual token stream do not have the same size\n"
				<< "Actual   : " << new_ts->size() << "\n"
				<< "Expected : " << tokens.size() << "\n"
				<< "\n"
				<< "Token Stream : " << ss.str();
		}

		return testing::AssertionSuccess();
	}

	void expectTokens(std::initializer_list<std::string> tokens)
	{
		EXPECT_PRED_FORMAT1(expectTokensPred, tokens);
	}

	std::stringstream input;
	std::string input_text;
	ParserDriver driver;
	std::shared_ptr<TokenStream> new_ts;
};

TEST_F(CloneTests,
StringExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		$str
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "$str");
	expectTokens({
		"$str"
	});
}

TEST_F(CloneTests,
StringWildcardExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str1 = "Hello"
		$str2 = "World"
	condition:
		$str*
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "$str*");
	expectTokens({
		"$str*"
	});
}

TEST_F(CloneTests,
StringAtExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		$str at 0x100
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "$str at 0x100");
	expectTokens({
		"$str",
		"at",
		"0x100"
	});
}

TEST_F(CloneTests,
StringInRangeExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		$str in (0x100 .. 0x200)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "$str in (0x100 .. 0x200)");
	expectTokens({
		"$str",
		"in",
		"(",
		"0x100",
		"..",
		"0x200",
		")"
	});
}

TEST_F(CloneTests,
StringCountExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		#str
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "#str");
	expectTokens({
		"#str",
	});
}

TEST_F(CloneTests,
StringOffsetExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		@str and @str[1]
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "@str and @str[1]");
	expectTokens({
		"@str",
		"and",
		"@str",
		"[",
		"1",
		"]"
	});
}

TEST_F(CloneTests,
StringLengthExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		!str and !str[1]
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "!str and !str[1]");
	expectTokens({
		"!str",
		"and",
		"!str",
		"[",
		"1",
		"]"
	});
}

TEST_F(CloneTests,
NotExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		not true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "not true");
	expectTokens({
		"not", "true"
	});
}

TEST_F(CloneTests,
PercentualExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		20% of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "20% of them");
	expectTokens({
		"20", "%", "of", "them"
	});
}

TEST_F(CloneTests,
DefinedExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		defined true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "defined true");
	expectTokens({
		"defined", "true"
	});
}

TEST_F(CloneTests,
UnaryMinusExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		-100
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "-100");
	expectTokens({
		"-", "100"
	});
}

TEST_F(CloneTests,
BitwiseNotExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		~100
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "~100");
	expectTokens({
		"~", "100"
	});
}

TEST_F(CloneTests,
AndExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		true and false and true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "true and false and true");
	expectTokens({
		"true", "and", "false", "and", "true"
	});
}

TEST_F(CloneTests,
OrExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		true or false or true
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "true or false or true");
	expectTokens({
		"true", "or", "false", "or", "true"
	});
}

TEST_F(CloneTests,
LtExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 < 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 < 2");
	expectTokens({
		"1", "<", "2"
	});
}

TEST_F(CloneTests,
GtExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 > 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 > 2");
	expectTokens({
		"1", ">", "2"
	});
}

TEST_F(CloneTests,
LeExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 <= 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 <= 2");
	expectTokens({
		"1", "<=", "2"
	});
}

TEST_F(CloneTests,
GeExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 >= 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 >= 2");
	expectTokens({
		"1", ">=", "2"
	});
}

TEST_F(CloneTests,
EqExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 == 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 == 2");
	expectTokens({
		"1", "==", "2"
	});
}

TEST_F(CloneTests,
NeqExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 != 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 != 2");
	expectTokens({
		"1", "!=", "2"
	});
}

TEST_F(CloneTests,
ContainsExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc" contains "abc"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "\"abc\" contains \"abc\"");
	expectTokens({
		"abc", "contains", "abc"
	});
}

TEST_F(CloneTests,
IcontainsExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc" icontains "abc"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "\"abc\" icontains \"abc\"");
	expectTokens({
		"abc", "icontains", "abc"
	});
}

TEST_F(CloneTests,
MatchesExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc" matches /abc/
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	ASSERT_TRUE(false) << "matches still needs support in regexes";

	EXPECT_EQ(cloned->getText(), "\"abc\" matches /abc/");
	expectTokens({
		"\"abc\"", "matches", "/abc/"
	});
}

TEST_F(CloneTests,
StartsWithExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc" startswith "abc"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "\"abc\" startswith \"abc\"");
	expectTokens({
		"abc", "startswith", "abc"
	});
}

TEST_F(CloneTests,
EndsWithExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc" endswith "abc"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "\"abc\" endswith \"abc\"");
	expectTokens({
		"abc", "endswith", "abc"
	});
}

TEST_F(CloneTests,
IstartsWithExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc" istartswith "abc"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "\"abc\" istartswith \"abc\"");
	expectTokens({
		"abc", "istartswith", "abc"
	});
}

TEST_F(CloneTests,
IendsWithExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc" iendswith "abc"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "\"abc\" iendswith \"abc\"");
	expectTokens({
		"abc", "iendswith", "abc"
	});
}

TEST_F(CloneTests,
IequalsExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc" iequals "abc"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "\"abc\" iequals \"abc\"");
	expectTokens({
		"abc", "iequals", "abc"
	});
}

TEST_F(CloneTests,
PlusExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 + 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 + 2");
	expectTokens({
		"1", "+", "2"
	});
}

TEST_F(CloneTests,
MinusExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 - 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 - 2");
	expectTokens({
		"1", "-", "2"
	});
}

TEST_F(CloneTests,
MultiplyExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 * 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 * 2");
	expectTokens({
		"1", "*", "2"
	});
}

TEST_F(CloneTests,
DivideExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 \ 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 \\ 2");
	expectTokens({
		"1", "\\", "2"
	});
}

TEST_F(CloneTests,
ModuloExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 % 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 % 2");
	expectTokens({
		"1", "%", "2"
	});
}

TEST_F(CloneTests,
BitwiseXorExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 ^ 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 ^ 2");
	expectTokens({
		"1", "^", "2"
	});
}

TEST_F(CloneTests,
BitwiseOrExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 | 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 | 2");
	expectTokens({
		"1", "|", "2"
	});
}

TEST_F(CloneTests,
BitwiseAndExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 & 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 & 2");
	expectTokens({
		"1", "&", "2"
	});
}

TEST_F(CloneTests,
ShiftLeftExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 << 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 << 2");
	expectTokens({
		"1", "<<", "2"
	});
}

TEST_F(CloneTests,
ShiftRightExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		1 >> 2
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "1 >> 2");
	expectTokens({
		"1", ">>", "2"
	});
}

TEST_F(CloneTests,
ForDictExpression) {
	prepareInput(
R"(
import "pe"

rule test
{
	condition:
		for any key, value in pe.version_info : (
			key == "CompanyName" and value == "Microsoft"
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "for any key, value in pe.version_info : ( key == \"CompanyName\" and value == \"Microsoft\" )");
	expectTokens({
		"for", "any", "key", ",", "value", "in", "pe", ".", "version_info", ":", "(", "\n",
		"key", "==", "CompanyName", "and", "value", "==", "Microsoft", "\n",
		")"
	});
}

TEST_F(CloneTests,
ForArrayExpression) {
	prepareInput(
R"(
import "pe"

rule test
{
	condition:
		for any section in pe.sections : (
			section.name == ".text"
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "for any section in pe.sections : ( section.name == \".text\" )");
	expectTokens({
		"for", "any", "section", "in", "pe", ".", "sections", ":", "(", "\n",
		"section", ".", "name", "==", ".text", "\n",
		")"
	});
}

TEST_F(CloneTests,
ForStringExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str1 = "Hello"
		$str2 = "World"
	condition:
		for any of ($str1, $str2) : (
			$ at 0x100
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "for any of ($str1, $str2) : ( $ at 0x100 )");
	expectTokens({
		"for", "any", "of", "(", "$str1", ",", "$str2", ")", ":", "(", "\n",
		"$", "at", "0x100", "\n",
		")"
	});
}

TEST_F(CloneTests,
IdExpression) {
	prepareInput(
R"(
rule abc { condition: false }

rule test
{
	condition:
		abc
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(2u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[1];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "abc");
	expectTokens({
		"abc"
	});
}

TEST_F(CloneTests,
StructAccessExpression) {
	prepareInput(
R"(
import "pe"

rule test
{
	condition:
		pe.is_pe
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "pe.is_pe");
	expectTokens({
		"pe", ".", "is_pe"
	});
}

TEST_F(CloneTests,
ArrayAccessExpression) {
	prepareInput(
R"(
import "pe"

rule test
{
	condition:
		pe.import_details[0].number_of_functions
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "pe.import_details[0].number_of_functions");
	expectTokens({
		"pe", ".", "import_details", "[", "0", "]", ".", "number_of_functions"
	});
}

TEST_F(CloneTests,
FunctionCallExpression) {
	prepareInput(
R"(
import "pe"

rule test
{
	condition:
		pe.imports("lib")
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "pe.imports(\"lib\")");
	expectTokens({
		"pe", ".", "imports", "(", "lib", ")"
	});
}

TEST_F(CloneTests,
BoolLiteralExpression) {
	prepareInput(
R"(
import "pe"

rule test
{
	condition:
		false
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "false");
	expectTokens({
		"false"
	});
}

TEST_F(CloneTests,
StringLiteralExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		"abc"
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "\"abc\"");
	expectTokens({
		"abc"
	});
}

TEST_F(CloneTests,
IntLiteralExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		42
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "42");
	expectTokens({
		"42"
	});
}

TEST_F(CloneTests,
DoubleLiteralExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		42.0
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "42.0");
	expectTokens({
		"42.0"
	});
}

TEST_F(CloneTests,
FilesizeExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		filesize
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "filesize");
	expectTokens({
		"filesize"
	});
}

TEST_F(CloneTests,
EntrypointExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		entrypoint
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "entrypoint");
	expectTokens({
		"entrypoint"
	});
}

TEST_F(CloneTests,
AllExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		all of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "all of them");
	expectTokens({
		"all", "of", "them"
	});
}

TEST_F(CloneTests,
AnyExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		any of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "any of them");
	expectTokens({
		"any", "of", "them"
	});
}

TEST_F(CloneTests,
NoneExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		none of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "none of them");
	expectTokens({
		"none", "of", "them"
	});
}

TEST_F(CloneTests,
ThemExpression) {
	prepareInput(
R"(
rule test
{
	strings:
		$str = "Hello"
	condition:
		2 of them
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "2 of them");
	expectTokens({
		"2", "of", "them"
	});
}

TEST_F(CloneTests,
ParenthesesExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		((1) and (2))
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "((1) and (2))");
	expectTokens({
		"(", "(", "1", ")", "and", "(", "2", ")", ")"
	});
}

TEST_F(CloneTests,
IntFunctionExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		uint8(1) == 0x10
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "uint8(1) == 0x10");
	expectTokens({
		"uint8", "(", "1", ")", "==", "0x10"
	});
}

TEST_F(CloneTests,
WithExpression) {
	prepareInput(
R"(
rule test
{
	condition:
		with a = 1, b = 2 : (
			with c = a + b : (
				c
			)
		)
}
)");

	EXPECT_TRUE(driver.parse(input));
	ASSERT_EQ(1u, driver.getParsedFile().getRules().size());
	const auto& rule = driver.getParsedFile().getRules()[0];

	auto cloned = rule->getCondition()->clone(new_ts);

	EXPECT_NE(rule->getCondition().get(), cloned.get());
	EXPECT_NE(rule->getCondition()->getTokenStream(), new_ts.get());

	EXPECT_EQ(cloned->getText(), "with a = 1, b = 2 : (with c = a + b : (c))");
	expectTokens({
		"with", "a", "=", "1", ",", "b", "=", "2", ":", "(", "\n",
		"with", "c", "=", "a", "+", "b", ":", "(", "\n",
		"c", "\n",
		")", "\n",
		")"
	});
}

}
}
