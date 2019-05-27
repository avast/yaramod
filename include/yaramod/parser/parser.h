/**
 * @file src/parser/parser_driver.h
 * @brief Declaration of class ParserDriver.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#pragma once

#include <fstream>
#include <iostream>
#include <limits.h>
#include <memory>
#include <vector>
#include <stack>
#include <string>

#include <pegtl/tao/pegtl.hpp>

#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/parser/parser_driver.h"

namespace pgl = TAO_PEGTL_NAMESPACE;

namespace yaramod {

class ParserDriver;

}  // namespace yaramod
