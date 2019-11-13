/**
 * @file src/yaramod.cpp
 * @brief Implementation of yaramod interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/yaramod.h"

namespace yaramod {

std::unique_ptr<YaraFile> Yaramod::parseFile(const std::string& filePath, ParserMode parserMode)
{
	_driver.reset(parserMode);
	_driver.setInput(filePath);
	if (!_driver.isValid())
		return nullptr;
	std::unique_ptr<YaraFile> result;
	if (_driver.parse())
		result = std::make_unique<YaraFile>(std::move(_driver.getParsedFile()));
	return result;
}

std::unique_ptr<YaraFile> Yaramod::parseStream(std::istream& inputStream, ParserMode parserMode)
{
	_driver.reset(parserMode);
	_driver.setInput(inputStream);
	std::unique_ptr<YaraFile> result;
	if (_driver.parse())
		result = std::make_unique<YaraFile>(std::move(_driver.getParsedFile()));
	return result;
}

}
