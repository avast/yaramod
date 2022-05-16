/**
* @file tests/cpp/test_yara_file.cpp
* @brief Tests for the YARA file.
* @copyright Avast Software s.r.o, All Rights Reserved.
*/

#include <gtest/gtest.h>

#include "yaramod/parser/parser_driver.h"
#include "yaramod/types/yara_file.h"

using namespace ::testing;

namespace yaramod {
namespace tests {

class YaraFileTests : public Test
{
public:
	YaraFileTests() : driver() {}

	yaramod::YaraFile parse(const std::string& inputText)
	{
		input.str(std::string());
		input.clear();
		input << inputText;
		driver.parse(input);
		return driver.getParsedFile();
	}

	std::stringstream input;
	ParserDriver driver;
};

TEST_F(YaraFileTests,
ExpandRuleFromOrigin) {
	auto yaraFile = parse(R"(
rule abc { condition: true }
rule rule1 { condition: true }
rule rule2 { condition: true }
rule rule3 { condition: true }
rule abd { condition: true }
rule rule4 { condition: true }
)");

	EXPECT_EQ(yaraFile.expandRulePrefixFromOrigin("non_existing", yaraFile.getRules()[5].get()), std::vector<std::string>{});
	EXPECT_EQ(yaraFile.expandRulePrefixFromOrigin("rule", yaraFile.getRules()[5].get()), (std::vector<std::string>{"rule1", "rule2", "rule3"}));
	EXPECT_EQ(yaraFile.expandRulePrefixFromOrigin("rule", yaraFile.getRules()[3].get()), (std::vector<std::string>{"rule1", "rule2"}));
	EXPECT_EQ(yaraFile.expandRulePrefixFromOrigin("rule", yaraFile.getRules()[2].get()), (std::vector<std::string>{"rule1"}));
	EXPECT_EQ(yaraFile.expandRulePrefixFromOrigin("rule", yaraFile.getRules()[1].get()), (std::vector<std::string>{}));
	EXPECT_EQ(yaraFile.expandRulePrefixFromOrigin("ab", yaraFile.getRules()[5].get()), (std::vector<std::string>{"abc", "abd"}));
	EXPECT_EQ(yaraFile.expandRulePrefixFromOrigin("ab", yaraFile.getRules()[4].get()), (std::vector<std::string>{"abc"}));
}

}
}
