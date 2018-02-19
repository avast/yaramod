/**
* @file tests/utils_tests.cpp
* @brief Tests for the YARA utility functions.
* @copyright AVG Technologies s.r.o, All Rights Reserved
*/

#include <gtest/gtest.h>

#include "yaramod/utils/utils.h"

using namespace ::testing;

namespace yaramod {
namespace tests {

class UtilsTests : public Test {};

TEST_F(UtilsTests,
IsValidIdentifierWorks) {
	EXPECT_TRUE(isValidIdentifier("xyz"));
	EXPECT_TRUE(isValidIdentifier("abc1"));
	EXPECT_TRUE(isValidIdentifier("_xyz"));
	EXPECT_TRUE(isValidIdentifier("_1"));
	EXPECT_FALSE(isValidIdentifier(""));
	EXPECT_FALSE(isValidIdentifier("123"));
}

TEST_F(UtilsTests,
EscapeStringWorks) {
	EXPECT_EQ(R"(abc)", escapeString("abc"));
	EXPECT_EQ(R"(a\nb)", escapeString("a\nb"));
	EXPECT_EQ(R"(\n\t\\\"\x01)", escapeString("\n\t\\\"\x01"));
}

}
}
