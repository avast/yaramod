#include <gtest/gtest.h>

#include <pog/precedence.h>

class TestPrecedence : public ::testing::Test {};

using namespace pog;

TEST_F(TestPrecedence,
Equality) {
	Precedence p1{1, Associativity::Left};
	Precedence p2{1, Associativity::Left};
	Precedence p3{1, Associativity::Right};
	Precedence p4{0, Associativity::Left};
	Precedence p5{2, Associativity::Left};

	EXPECT_EQ(p1, p2);
	EXPECT_NE(p1, p3);
	EXPECT_NE(p1, p4);
	EXPECT_NE(p1, p5);
}

TEST_F(TestPrecedence,
SameLevelLeftAssociative) {
	EXPECT_FALSE(
		(Precedence{1, Associativity::Left}) < (Precedence{1, Associativity::Left})
	);
	EXPECT_TRUE(
		(Precedence{1, Associativity::Left}) > (Precedence{1, Associativity::Left})
	);
}

TEST_F(TestPrecedence,
SameLevelRightAssociative) {
	EXPECT_TRUE(
		(Precedence{1, Associativity::Right}) < (Precedence{1, Associativity::Right})
	);
	EXPECT_FALSE(
		(Precedence{1, Associativity::Right}) > (Precedence{1, Associativity::Right})
	);
}

TEST_F(TestPrecedence,
LowerLevelLeftAssociative) {
	EXPECT_TRUE(
		(Precedence{0, Associativity::Left}) < (Precedence{1, Associativity::Left})
	);
	EXPECT_FALSE(
		(Precedence{0, Associativity::Left}) > (Precedence{1, Associativity::Left})
	);
}

TEST_F(TestPrecedence,
LowerLevelRightAssociative) {
	EXPECT_TRUE(
		(Precedence{0, Associativity::Right}) < (Precedence{1, Associativity::Right})
	);
	EXPECT_FALSE(
		(Precedence{0, Associativity::Right}) > (Precedence{1, Associativity::Right})
	);
}

TEST_F(TestPrecedence,
HigherLevelLeftAssociative) {
	EXPECT_FALSE(
		(Precedence{2, Associativity::Left}) < (Precedence{1, Associativity::Left})
	);
	EXPECT_TRUE(
		(Precedence{2, Associativity::Left}) > (Precedence{1, Associativity::Left})
	);
}

TEST_F(TestPrecedence,
HigherLevelRightAssociative) {
	EXPECT_FALSE(
		(Precedence{2, Associativity::Right}) < (Precedence{1, Associativity::Right})
	);
	EXPECT_TRUE(
		(Precedence{2, Associativity::Right}) > (Precedence{1, Associativity::Right})
	);
}
