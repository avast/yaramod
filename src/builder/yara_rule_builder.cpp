/**
 * @file src/builder/yara_rule_builder.cpp
 * @brief Implementation of class YaraRuleBuilder.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/types/expressions.h"
#include "yaramod/types/plain_string.h"
#include "yaramod/types/regexp.h"
#include "yaramod/utils/utils.h"

namespace yaramod {

/**
 * Constructor.
 */
YaraRuleBuilder::YaraRuleBuilder() : _name("unknown"), _mod(Rule::Modifier::None), _tags(), _metas(),
	_strings(std::make_shared<Rule::StringsTrie>()), _condition(std::make_shared<BoolLiteralExpression>(true))
{
}

/**
 * Returns the built YARA rule and resets the builder back to default state.
 *
 * @return Built YARA rule.
 */
std::unique_ptr<Rule> YaraRuleBuilder::get()
{
	// If rule has invalid name
	if (!isValidIdentifier(_name))
		return nullptr;

	// If any of the meta information has invalid key identifier
	if (std::any_of(_metas.begin(), _metas.end(),
				[](const auto& meta) {
					return !isValidIdentifier(meta.getKey());
				}))
	{
		return nullptr;
	}

	auto rule = std::make_unique<Rule>(std::move(_name), _mod, std::move(_metas), std::move(_strings), std::move(_condition), std::move(_tags));
	_name = "unknown";
	_mod = Rule::Modifier::None;
	_tags.clear();
	_metas.clear();
	_strings = std::make_shared<Rule::StringsTrie>();
	_condition = std::make_shared<BoolLiteralExpression>(true);
	return rule;
}

/**
 * Sets name to a rule.
 *
 * @param name Name.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withName(const std::string& name)
{
	_name = name;
	return *this;
}

/**
 * Sets modifier to a rule.
 *
 * @param mod Modifier.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withModifier(Rule::Modifier mod)
{
	_mod = mod;
	return *this;
}

/**
 * Adds tag to a rule.
 *
 * @param tag Tag.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withTag(const std::string& tag)
{
	_tags.push_back(tag);
	return *this;
}

/**
 * Adds a string meta information to a rule.
 *
 * @param key Key of meta.
 * @param value String value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withStringMeta(const std::string& key, const std::string& value)
{
	_metas.emplace_back(key, Literal(value, Literal::Type::String));
	return *this;
}

/**
 * Adds an integer meta information to a rule.
 *
 * @param key Key of meta.
 * @param value Integer value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withIntMeta(const std::string& key, std::int64_t value)
{
	_metas.emplace_back(key, Literal(numToStr(value), Literal::Type::Int));
	return *this;
}

/**
 * Adds an unsigned integer meta information to a rule.
 *
 * @param key Key of meta.
 * @param value Unsigned integer value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withUIntMeta(const std::string& key, std::uint64_t value)
{
	_metas.emplace_back(key, Literal(numToStr(value), Literal::Type::Int));
	return *this;
}

/**
 * Adds a hexadecimal integer meta information to a rule.
 *
 * @param key Key of meta.
 * @param value Hexadecimal integer value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withHexIntMeta(const std::string& key, std::uint64_t value)
{
	_metas.emplace_back(key, Literal(numToStr(value, std::hex, true), Literal::Type::Int));
	return *this;
}

/**
 * Adds a boolean meta information to a rule.
 *
 * @param key Key of meta.
 * @param value Boolean value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withBoolMeta(const std::string& key, bool value)
{
	_metas.emplace_back(key, Literal(value));
	return *this;
}

/**
 * Adds a plain string to a rule.
 *
 * @param id Identifier of the string.
 * @param value Plain string text.
 * @param mods Modifiers.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withPlainString(const std::string& id, const std::string& value, std::uint32_t mods)
{
	auto plainString = std::make_shared<PlainString>(value);
	plainString->setIdentifier(id);
	plainString->setModifiers(mods);
	_strings->insert(id, std::static_pointer_cast<String>(plainString));
	return *this;
}

/**
 * Adds a hex string to a rule.
 *
 * @param id Identifier of the string.
 * @param hexString Hex string.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withHexString(const std::string& id, const std::shared_ptr<HexString>& hexString)
{
	hexString->setIdentifier(id);
	_strings->insert(id, std::static_pointer_cast<String>(hexString));
	return *this;
}

/**
 * Adds a regular expression string to a rule.
 *
 * @todo Regular expressions are now only handled as strings from
 * the builder point of view.
 *
 * @param id Identifier of the string.
 * @param value Regular expression.
 * @param suffixMods Suffix modifiers of regular expression.
 * @param mods Modifiers.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withRegexp(const std::string& id, const std::string& value,
		const std::string& suffixMods, std::uint32_t mods)
{
	auto regexp = std::make_shared<Regexp>(std::make_shared<RegexpText>(value));
	regexp->setIdentifier(id);
	regexp->setModifiers(mods);
	regexp->setSuffixModifiers(suffixMods);
	_strings->insert(id, std::static_pointer_cast<String>(regexp));
	return *this;
}

/**
 * Sets a condition to a rule.
 *
 * @param condition Condition.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withCondition(Expression::Ptr&& condition)
{
	_condition = std::move(condition);
	return *this;
}

/**
 * Sets a condition to a rule.
 *
 * @param condition Condition.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withCondition(const Expression::Ptr& condition)
{
	_condition = condition;
	return *this;
}

}
