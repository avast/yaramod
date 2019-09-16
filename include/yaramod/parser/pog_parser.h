/**
 * @file src/parser/parser_driver.h
 * @brief Declaration of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <pog/pog.h>
#include "yaramod/parser/parser_driver.h"


namespace yaramod {
using Value = std::variant<int, bool, std::string, TokenIt>;
pog::Parser<Value> parser;
parser.token


} // namespace yaramod
