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
 * Default constructor creates new TokenStream.
 */
YaraRuleBuilder::YaraRuleBuilder()
	: YaraRuleBuilder(std::make_shared<TokenStream>())
{
}

/**
 * Constructor.
 * @param tokenStream: Already existing TokenStream
 */
YaraRuleBuilder::YaraRuleBuilder(std::shared_ptr<TokenStream> tokenStream)
	: _tokenStream(tokenStream)
	, _name(std::nullopt)
	, _mod(std::nullopt)
	, _strings(std::make_shared<Rule::StringsTrie>())
	, _condition(std::make_shared<BoolLiteralExpression>(true))
{
	withName("unknown");
}


/**
 * Returns the built YARA rule and resets the builder back to default state.
 *
 * @return Built YARA rule.
 */
std::unique_ptr<Rule> YaraRuleBuilder::get()
{
	std::cout << "get() called" << std::endl;
	// If rule has invalid name
	if(!_name.has_value()){
		std::cerr << "Unspecified name" << std::endl;
		return nullptr;
	}
	if (!isValidIdentifier((*_name)->getPureText())) {
		std::cerr << "Invalid name identifier '" << (*_name)->getPureText() << "'" << std::endl;
		return nullptr;
	}

	// If any of the meta information has invalid key identifier
	if (std::any_of(_metas.begin(), _metas.end(),
				[](const auto& meta) {
					std::cout << meta.getKey() << std::endl;
					return !isValidIdentifier(meta.getKey());
				}))
	{
		std::cerr << "Invalid key identifier" << std::endl;
		return nullptr;
	}

	std::cout << "TokenStream when rule_builder.get() called: '" << *_tokenStream << "'" << std::endl;
	auto rule = std::make_unique<Rule>(std::move(_tokenStream), std::move(*_name), std::move(_mod), std::move(_metas), std::move(_strings), std::move(_condition), std::move(_tags));
	_tokenStream = std::make_shared<TokenStream>();
	_name = std::nullopt;
	_mod = std::nullopt;
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
	if(name == "")
		throw RuleBuilderError("Error: name must be non-empty.");
	if(_name != std::nullopt)
		(*_name)->setValue(name);
	else
		_name = _tokenStream->emplace_back(TokenType::RULE_NAME, name);
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
	if(_mod != std::nullopt)
		throw RuleBuilderError("Error: Rule already has modifier.");
	if(mod == Rule::Modifier::Global)
		_mod = _tokenStream->emplace_back(TokenType::GLOBAL, "global");
	else if(mod == Rule::Modifier::Private)
		_mod = _tokenStream->emplace_back(TokenType::PRIVATE, "private");
	else{
		assert(mod == Rule::Modifier::None);
		_mod = std::nullopt;
	}
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
	if(tag == "")
		throw RuleBuilderError("Error: tag must be non-empty.");
	TokenIt it = _tokenStream->emplace_back(TokenType::TAG, tag);
	_tags.push_back(it);
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
	if(key == "" || value == "")
		throw RuleBuilderError("Error: String-Meta key and value must be non-empty.");

	auto itKey = _tokenStream->emplace_back( TokenType::META_KEY, key );
	_tokenStream->emplace_back( TokenType::EQ, Literal(" = ") );
	auto itValue = _tokenStream->emplace_back( TokenType::META_VALUE, value );

	_metas.emplace_back(itKey, itValue);
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
YaraRuleBuilder& YaraRuleBuilder::withIntMeta(const std::string& key, std::int64_t value, const std::optional<std::string>& formated_value/* = std::nullopt*/ )
{
	if(key == "")
		throw RuleBuilderError("Error: Int-Meta key must be non-empty.");

	auto itKey = _tokenStream->emplace_back( TokenType::META_KEY, key );
	_tokenStream->emplace_back( TokenType::EQ, Literal(" = ") );
	auto itValue = _tokenStream->emplace_back( TokenType::META_VALUE, value, formated_value );

	_metas.emplace_back(itKey, itValue);
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
YaraRuleBuilder& YaraRuleBuilder::withUIntMeta(const std::string& key, std::uint64_t value, const std::optional<std::string>& formated_value/* = std::nullopt*/ )
{
	if(key == "")
		throw RuleBuilderError("Error: UInt-Meta key must be non-empty.");

	auto itKey = _tokenStream->emplace_back( TokenType::META_KEY, key );
	_tokenStream->emplace_back( TokenType::EQ, Literal(" = ") );
	auto itValue = _tokenStream->emplace_back( TokenType::META_VALUE, value, formated_value );

	_metas.emplace_back(itKey, itValue);
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
YaraRuleBuilder& YaraRuleBuilder::withHexIntMeta(const std::string& key, std::uint64_t value, const std::optional<std::string>& formated_value/* = std::nullopt*/ )
{
	if(key == "")
		throw RuleBuilderError("Error: HexInt-Meta key must be non-empty.");

	auto itKey = _tokenStream->emplace_back( TokenType::META_KEY, key );
	_tokenStream->emplace_back( TokenType::EQ, Literal(" = ") );
	TokenIt itValue;
	if(!formated_value.has_value())
		itValue = _tokenStream->emplace_back( TokenType::META_VALUE, value, std::make_optional<std::string>(numToStr(value, std::hex, true)) );
	else
		itValue = _tokenStream->emplace_back( TokenType::META_VALUE, value, formated_value );
	_metas.emplace_back(itKey, itValue);
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
	if(key == "")
		throw RuleBuilderError("Error: Bool-Meta key must be non-empty.");

	auto itKey = _tokenStream->emplace_back( TokenType::META_KEY, std::move(Literal(key)) );
	_tokenStream->emplace_back( TokenType::EQ, Literal(" = ") );
	auto itValue = _tokenStream->emplace_back( TokenType::META_VALUE, std::move(Literal(value)) );

	_metas.emplace_back(itKey, itValue);
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
	//Must insert into tokenstream: id, =, ", value, ", mods
	if(id == "" || value == "")
		throw RuleBuilderError("Error: Plain string id and value must be non-empty.");
	TokenIt id_token = _tokenStream->emplace_back(TokenType::STRING_KEY, id);
	_tokenStream->emplace_back(TokenType::EQ, "=");
	_tokenStream->emplace_back(TokenType::LQUOTE, "\"");
	auto plainString = std::make_shared<PlainString>(_tokenStream, value);
	plainString->setIdentifier(id_token);
	_tokenStream->emplace_back(TokenType::RQUOTE, "\"");
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
	if(id == "" || hexString->getText() == "")
		throw RuleBuilderError("Error: Hex string id and value must be non-empty.");
	_tokenStream->move_append(std::move(hexString->_tokenStream.get()));
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
	if(id == "" || value == "")
		throw RuleBuilderError("Error: Regexp id and value must be non-empty.");
	auto regexp = std::make_shared<Regexp>(_tokenStream, std::make_shared<RegexpText>(value));
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

} //namespace yaramod
