/**
 * @file src/parser/uid_generator.h
 * @brief Declaration of class UidGenerator.
 * @copyright (c) 2022 Avast Software, licensed under the MIT license
*/

#pragma once

#include <cstdint>

namespace yaramod {

/**
 * Class that deterministically generates 
 * up to 2^64 unique IDs for AST nodes
 *
 * The IDs are unique for a given input
 * so only pair (input; node) has a UID
 * This means UidGenerator has to be reset
 * For every new input
 */
class UidGenerator 
{
public:
	std::uint64_t next() { return _counter++; }
	void reset() { _counter = 0; }

private:
	std::uint64_t _counter = 0;
};

} // namespace yaramod
