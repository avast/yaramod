/**
* @file tests/literal_tests.cpp
* @brief Tests for the YARA literal.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>
#include <iostream>

// #include "yaramod/builder/yara_expression_builder.h"
// #include "yaramod/builder/yara_file_builder.h"
// #include "yaramod/builder/yara_hex_string_builder.h"
// #include "yaramod/builder/yara_rule_builder.h"
// #include "yaramod/types/expressions.h"
#include "yaramod/types/literal.h"
#include "yaramod/types/meta.h"

using namespace ::testing;

namespace yaramod {
namespace tests {

class LiteralTests : public Test {};

TEST_F(LiteralTests,
TokenStreamFindSimple) {
   TokenStream ts;

   auto found = ts.find(TokenType::META_KEY);
   ASSERT_EQ(found, ts.end());
   TokenIt key = ts.emplace_back(TokenType::META_KEY, "author");
   found = ts.find(TokenType::META_KEY);
   ASSERT_EQ(found, key);
}

TEST_F(LiteralTests,
TokenStreamFind) {
   TokenStream ts;
   TokenIt c1 = ts.emplace_back(TokenType::COMMENT, "/*c1*/");
   ts.emplace_back(TokenType::COMMENT, "/*c2*/");
   TokenIt k1 = ts.emplace_back(TokenType::META_KEY, "k1");
   TokenIt c3 = ts.emplace_back(TokenType::COMMENT, "/*c3*/");
   ts.emplace_back(TokenType::META_KEY, "k2");
   TokenIt c4 = ts.emplace_back(TokenType::COMMENT, "/*c4*/");
   ts.emplace_back(TokenType::COMMENT, "/*c5*/");
   ts.emplace_back(TokenType::META_KEY, "k3");

   ASSERT_EQ(ts.find(COMMENT), c1);
   ASSERT_EQ(ts.find(COMMENT, k1), c3);
   ASSERT_EQ(ts.find(COMMENT, c3), c3);
   ASSERT_EQ(ts.find(META_VALUE),         ts.end());
   ASSERT_EQ(ts.find(META_VALUE, c1),     ts.end());
   ASSERT_EQ(ts.find(META_VALUE, c1, c4), c4      );
}

TEST_F(LiteralTests,
TokenStreamEmplaceBack) {
   TokenStream ts;

   TokenIt key = ts.emplace_back(TokenType::META_KEY, "author");
   ts.emplace_back(TokenType::EQ, "=");
   TokenIt value = ts.emplace_back(TokenType::META_VALUE, "Mr. Avastian");
   ASSERT_EQ(key->getPureText(), "author");
   ASSERT_EQ(value->getPureText(), "Mr. Avastian");
}

TEST_F(LiteralTests,
TokenStreamEmplace) {
   TokenStream ts;

   auto key = ts.emplace_back(TokenType::META_KEY, "author");
   ts.emplace_back(TokenType::EQ, "=");
   auto value = ts.emplace_back(TokenType::META_VALUE, "Mr. Avastian");
   auto comment = ts.emplace(value, TokenType::COMMENT, "/*comment about the author*/");
   ASSERT_EQ(key->getPureText(), "author");
   ASSERT_EQ(value->getPureText(), "Mr. Avastian");
   ASSERT_EQ(comment->getPureText(), "/*comment about the author*/");
}

TEST_F(LiteralTests,
TokenStreamPushBack) {
   TokenStream ts;
   Token t(TokenType::RULE_NAME, Literal("rule_name"));
   TokenIt name = ts.push_back(t);
   ASSERT_EQ(name->getPureText(), "rule_name");
}

TEST_F(LiteralTests,
TokenStreamErase) {
   TokenStream ts;
   TokenIt key = ts.emplace_back(TokenType::META_KEY, "author");
   ts.emplace_back(TokenType::META_KEY, "=");
   TokenIt comment1 = ts.emplace_back(TokenType::COMMENT, "/*comment before author name*/");
   TokenIt value = ts.emplace_back(TokenType::META_KEY, "author_name");
   TokenIt comment2 = ts.emplace_back(TokenType::COMMENT, "/*comment after author name*/");

   TokenIt behindErased = ts.erase(comment1);
   ASSERT_EQ(behindErased, value);
   behindErased = ts.erase(key, comment2);
   ASSERT_EQ(behindErased, comment2);
   ASSERT_EQ(comment2->getPureText(), "/*comment after author name*/");

   ts.clear();
   ASSERT_EQ(ts.size(), 0);
   ASSERT_TRUE(ts.empty());
}

}
}
