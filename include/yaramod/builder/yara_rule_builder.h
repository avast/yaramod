/**
 * @file src/builder/yara_rule_builder.h
 * @brief Declaration of class YaraRuleBuilder.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>

#include <yaramod/yaramod_error.h>
#include "yaramod/types/hex_string.h"
#include "yaramod/types/rule.h"

namespace yaramod {

/**
 * Represents error during building.
 */
class RuleBuilderError : public YaramodError
{
public:
	RuleBuilderError(const std::string& errorMsg) : YaramodError(errorMsg) {}
	RuleBuilderError(const RuleBuilderError&) = default;
};

/**
 * Class representing builder of YARA rules. You use this builder
 * to specify what you want in your YARA rule and then you can obtain
 * your YARA rule by calling method @c get. As soon as @c get is called,
 * builder resets to default state and does not contain any data from
 * the previous build process.
 */
class YaraRuleBuilder
{
public:
	/// @name Constructor
	/// @{
	YaraRuleBuilder();
	YaraRuleBuilder(std::shared_ptr<TokenStream> tokenStream);
	/// @}

	/// @name Build method
	/// @{
	std::unique_ptr<Rule> get();
	/// @}

	/// @name Building methods
	/// @{
	YaraRuleBuilder& withName(const std::string& name);
	YaraRuleBuilder& withModifier(Rule::Modifier mod);
	YaraRuleBuilder& withTag(const std::string& tag);

	YaraRuleBuilder& withStringMeta(const std::string& key, const std::string& value);
	YaraRuleBuilder& withIntMeta(const std::string& key, std::int64_t value, const std::optional<std::string>& formated_value = std::nullopt);
	YaraRuleBuilder& withUIntMeta(const std::string& key, std::uint64_t value, const std::optional<std::string>& formated_value = std::nullopt);
	YaraRuleBuilder& withHexIntMeta(const std::string& key, std::uint64_t value, const std::optional<std::string>& formated_value = std::nullopt);
	YaraRuleBuilder& withBoolMeta(const std::string& key, bool value);

	YaraRuleBuilder& withPlainString(const std::string& id, const std::string& value, std::uint32_t mods = String::Modifiers::Ascii);
	YaraRuleBuilder& withHexString(const std::string& id, const std::shared_ptr<HexString>& hexString);
	YaraRuleBuilder& withRegexp(const std::string& id, const std::string& value,
			const std::string& suffixMods = "", std::uint32_t mods = String::Modifiers::Ascii);

	YaraRuleBuilder& withCondition(Expression::Ptr&& condition);
	YaraRuleBuilder& withCondition(const Expression::Ptr& condition);
	/// @}

private:
	std::shared_ptr<TokenStream> _tokenStream; ///< Storage of all Tokens
	std::optional<TokenIt> _name; ///< Name
	std::optional<TokenIt> _mod; ///< Modifier
	std::vector<TokenIt> _tags; ///< Tags
	std::vector<Meta> _metas; ///< Meta information
	std::shared_ptr<Rule::StringsTrie> _strings; ///< Strings
	Expression::Ptr _condition; ///< Condition expression
};

}
