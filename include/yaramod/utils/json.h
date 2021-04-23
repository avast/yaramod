/**
 * @file include/yaramod/utils/json.h
 * @brief Declaration of utility functions.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#pragma once

#include <json/json.hpp>

namespace yaramod {

nlohmann::json readJsonFile(const std::string& filePath);
nlohmann::json readJsonString(const std::string& jsonString);

template<typename T>
T accessJson(const nlohmann::json& json, const std::string& key);
std::string accessJsonString(const nlohmann::json& json, const std::string& key);
std::vector<nlohmann::json> accessJsonArray(const nlohmann::json& json, const std::string& key);
nlohmann::json accessJsonSubjson(const nlohmann::json& json, const std::string& key);

}
