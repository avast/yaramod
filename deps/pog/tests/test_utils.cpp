#include <gtest/gtest.h>

#include <pog/utils.h>

class TestUtils : public ::testing::Test {};

TEST_F(TestUtils,
transform_if) {
	std::vector<int> v{0, 1, 2, 3, 4, 5, 6};

	std::vector<int> result;
	pog::transform_if(v.begin(), v.end(), std::back_inserter(result),
		[](auto i) { return i % 2 == 0; },
		[](auto i) { return i + 10; }
	);
	EXPECT_EQ(result, (std::vector<int>{10, 12, 14, 16}));

	result.clear();
	pog::transform_if(v.begin(), v.end(), std::back_inserter(result),
		[](auto i) { return i < 100; },
		[](auto i) { return i + 10; }
	);
	EXPECT_EQ(result, (std::vector<int>{10, 11, 12, 13, 14, 15, 16}));

	result.clear();
	pog::transform_if(v.begin(), v.end(), std::back_inserter(result),
		[](auto i) { return i > 100; },
		[](auto i) { return i + 10; }
	);
	EXPECT_EQ(result, (std::vector<int>{}));
}

TEST_F(TestUtils,
accumulate_if) {
	std::vector<int> v{1, 2, 3, 4, 5, 6};

	auto result = pog::accumulate_if(v.begin(), v.end(), 0,
		[](auto i) { return i % 2 == 0; },
		[](auto res, auto i) { return res + i; }
	);
	EXPECT_EQ(result, 12);

	result = pog::accumulate_if(v.begin(), v.end(), 0,
		[](auto i) { return i < 100; },
		[](auto res, auto i) { return res + i; }
	);
	EXPECT_EQ(result, 21);

	result = pog::accumulate_if(v.begin(), v.end(), 0,
		[](auto i) { return i > 100; },
		[](auto res, auto i) { return res + i; }
	);
	EXPECT_EQ(result, 0);
}

TEST_F(TestUtils,
hash_combine) {
	EXPECT_EQ(pog::hash_combine(1, 2), pog::hash_combine(1, 2));
	EXPECT_NE(pog::hash_combine(1, 2), pog::hash_combine(1, 3));
	EXPECT_NE(pog::hash_combine(1, 2), pog::hash_combine(2, 1));
	EXPECT_NE(pog::hash_combine(1, 2), pog::hash_combine(1, 2, 3));
}
