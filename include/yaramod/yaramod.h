/**
 * @file src/yaramod.h
 * @brief Declaration of yaramod interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define YARAMOD_VERSION_MAJOR 2
#define YARAMOD_VERSION_MINOR 12
#define YARAMOD_VERSION_PATCH 1
#define YARAMOD_VERSION_ADDEND ""

#define YARAMOD_VERSION STR(YARAMOD_VERSION_MAJOR) "." STR(YARAMOD_VERSION_MINOR) "." STR(YARAMOD_VERSION_PATCH) YARAMOD_VERSION_ADDEND

#define YARA_SYNTAX_VERSION "3.10"

#include <memory>

#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/parser/parser_driver.h"
#include "yaramod/types/yara_file.h"

namespace yaramod {

std::unique_ptr<YaraFile> parseFile(const std::string& filePath, ParserMode parseMode = ParserMode::Regular);
std::unique_ptr<YaraFile> parseStream(std::istream& inputStream, ParserMode parseMode = ParserMode::Regular);

}
