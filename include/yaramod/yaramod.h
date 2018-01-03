/**
 * @file src/yaramod.h
 * @brief Declaration of yaramod interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>

#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/parser/parser_driver.h"
#include "yaramod/types/yara_file.h"

namespace yaramod {

std::unique_ptr<YaraFile> parseFile(const std::string& filePath, ParserMode parseMode = ParserMode::Regular);
std::unique_ptr<YaraFile> parseStream(std::istream& inputStream, ParserMode parseMode = ParserMode::Regular);

}
