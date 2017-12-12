/**
 * @file src/utils/utils.h
 * @brief Declaration of utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <sstream>
#include <string>

namespace yaramod {

bool isValidIdentifier(const std::string& id);
std::string escapeString(const std::string& str);

}
