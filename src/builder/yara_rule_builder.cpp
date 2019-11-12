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
YaraRuleBuilder::YaraRuleBuilder(const std::shared_ptr<TokenStream>& tokenStream)
	: _tokenStream(tokenStream)
	, _mod(std::nullopt)
	, _strings(std::make_shared<Rule::StringsTrie>())
{
	resetTokens();
}

/**
 * Returns the built YARA rule and resets the builder back to default state.
 *
 * @return Built YARA rule.
 */
std::unique_ptr<Rule> YaraRuleBuilder::get()
{
	if (!isValidIdentifier(_name_it->getPureText()))
	{
		std::stringstream err;
		err << "Invalid name identifier '" << _name_it->getPureText() << "'" << std::endl;
		throw RuleBuilderError("Error: " + err.str());
		return nullptr;
	}

	// If any of the meta information has invalid key identifier
	if (std::any_of(_metas.begin(), _metas.end(),
				[](const auto& meta) {
					return !isValidIdentifier(meta.getKey());
				}))
	{
		throw RuleBuilderError("Error: Invalid key identifier");
	}

	if (!_condition)
	{
		_condition = std::make_shared<BoolLiteralExpression>(_tokenStream->emplace(_rcb, BOOL_TRUE, true));
		_tokenStream->emplace(_rcb, NEW_LINE, "\n");
	}

	auto rule = std::make_unique<Rule>(std::move(_tokenStream), std::move(_name_it), std::move(_mod), std::move(_metas), std::move(_strings), std::move(_condition), std::move(_tags));

	_tokenStream = std::make_shared<TokenStream>();
	resetTokens();

	_mod = std::nullopt;
	_tags.clear();
	_metas.clear();
	_strings = std::make_shared<Rule::StringsTrie>();

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
	if (name == std::string{})
		throw RuleBuilderError("Error: name must be non-empty.");
	_name_it->setValue(name);
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
	if (_mod != std::nullopt)
		throw RuleBuilderError("Error: Rule already has modifier.");
	if (mod == Rule::Modifier::Global)
		_mod = _tokenStream->emplace(_rule_it, TokenType::GLOBAL, "global");
	else if (mod == Rule::Modifier::Private)
		_mod = _tokenStream->emplace(_rule_it, TokenType::PRIVATE, "private");
	else
	{
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
	if (tag == std::string{})
		throw RuleBuilderError("Error: tag must be non-empty.");
	if (_tags.empty())
		_tokenStream->emplace(_lcb, COLON, ":");
	TokenIt it = _tokenStream->emplace(_lcb, TokenType::TAG, tag);
	_tags.push_back(it);
	return *this;
}

/**
 * Adds comment to a rule.
 *
 * @param comment Comment.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withComment(const std::string& comment, bool multiline)
{
	if (comment == std::string{})
		throw RuleBuilderError("Error: comment must be non-empty.");
	TokenIt insert_before = _mod.value_or(_rule_it);
	std::stringstream ss;
	if (multiline)
	{
		ss << "/* " << comment << " */";
		_tokenStream->emplace(insert_before, TokenType::COMMENT, ss.str());
	}
	else
	{
		for (auto item : comment)
			if (item == '\n')
				throw RuleBuilderError("Error: one-line comment must not contain \\n.");
		ss << "// " << comment;
		_tokenStream->emplace(insert_before, TokenType::ONELINE_COMMENT, ss.str());
	}
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");
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
	if (key == std::string{} || value == std::string{})
		throw RuleBuilderError("Error: String-Meta key and value must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, META, "meta");
		_tokenStream->emplace(insert_before, COLON, ":");
		_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");
	}

	auto itKey = _tokenStream->emplace(insert_before, TokenType::META_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::META_VALUE, escapeString(value));
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

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
YaraRuleBuilder& YaraRuleBuilder::withIntMeta(const std::string& key, std::int64_t value)
{
	if (key == std::string{})
		throw RuleBuilderError("Error: Int-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, META, "meta");
		_tokenStream->emplace(insert_before, COLON, ":");
		_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");
	}

	auto itKey = _tokenStream->emplace(insert_before, TokenType::META_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::EQ, Literal("="));
	auto itValue = _tokenStream->emplace(insert_before, TokenType::META_VALUE, value);
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

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
YaraRuleBuilder& YaraRuleBuilder::withUIntMeta(const std::string& key, std::uint64_t value)
{
	if (key == std::string{})
		throw RuleBuilderError("Error: UInt-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, META, "meta");
		_tokenStream->emplace(insert_before, COLON, ":");
		_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");
	}

	auto itKey = _tokenStream->emplace(insert_before, TokenType::META_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::EQ, Literal("="));
	auto itValue = _tokenStream->emplace(insert_before, TokenType::META_VALUE, value);
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

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
YaraRuleBuilder& YaraRuleBuilder::withHexIntMeta(const std::string& key, std::uint64_t value)
{
	if (key == std::string{})
		throw RuleBuilderError("Error: HexInt-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, META, "meta");
		_tokenStream->emplace(insert_before, COLON, ":");
		_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");
	}

	auto itKey = _tokenStream->emplace(insert_before, TokenType::META_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::EQ, Literal("="));
	auto itValue = _tokenStream->emplace(insert_before, TokenType::META_VALUE, value, std::make_optional<std::string>(numToStr(value, std::hex, true)));
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

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
	if (key == std::string{})
		throw RuleBuilderError("Error: Bool-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, META, "meta");
		_tokenStream->emplace(insert_before, COLON, ":");
		_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");
	}

	auto itKey = _tokenStream->emplace(insert_before, TokenType::META_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::META_VALUE, value);
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

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
	if (id == std::string{} || value == std::string{})
		throw RuleBuilderError("Error: Plain string id and value must be non-empty.");
	if (!_strings_it.has_value())
		initializeStrings();

	TokenIt id_token = _tokenStream->emplace(_condition_it, TokenType::STRING_KEY, id);
	_tokenStream->emplace(_condition_it, TokenType::ASSIGN, "=");

	auto temporary = std::make_shared<TokenStream>();
	auto plainString = std::make_shared<PlainString>(temporary, escapeString(value));
	plainString->setModifiers(mods, true);
	plainString->setIdentifier(id_token);

	_tokenStream->move_append(temporary.get(), _condition_it);
	_tokenStream->emplace(_condition_it, NEW_LINE, "\n");

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
	if (id == std::string{} || hexString->getText() == std::string{})
		throw RuleBuilderError("Error: Hex string id and value must be non-empty.");
	if (!_strings_it.has_value())
		initializeStrings();

	hexString->setIdentifier(id);
	_tokenStream->move_append(hexString->getTokenStream().get(), _condition_it);
	_tokenStream->emplace(_condition_it, NEW_LINE, "\n");

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
	if (id == std::string{} || value == std::string{})
		throw RuleBuilderError("Error: Regexp id and value must be non-empty.");
	if (!_strings_it.has_value())
		initializeStrings();

	auto temporary = std::make_shared<TokenStream>();
	auto regexp = std::make_shared<Regexp>(temporary, std::make_shared<RegexpText>(value));
	regexp->setIdentifier(id);
	regexp->setModifiers(mods, true);
	regexp->setSuffixModifiers(suffixMods);

	_tokenStream->move_append(temporary.get(), _condition_it);
	_tokenStream->emplace(_condition_it, NEW_LINE, "\n");
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
	_tokenStream->move_append(_condition->getTokenStream(), _rcb);
	_tokenStream->emplace(_rcb, NEW_LINE, "\n");
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
	_tokenStream->move_append(_condition->getTokenStream(), _rcb);
	_tokenStream->emplace(_rcb, NEW_LINE, "\n");
	return *this;
}

void YaraRuleBuilder::initializeStrings()
{
	_strings_it = _tokenStream->emplace(_condition_it, STRINGS, "strings");
	_tokenStream->emplace(_condition_it, COLON, ":");
	_tokenStream->emplace(_condition_it, NEW_LINE, "\n");
}

void YaraRuleBuilder::resetTokens()
{
	_rule_it = _tokenStream->emplace_back(RULE, "rule");
	_name_it = _tokenStream->emplace_back(RULE_NAME, "unknown");
	_lcb = _tokenStream->emplace_back(RULE_BEGIN, "{");
	_tokenStream->emplace_back(NEW_LINE, "\n");
	_strings_it = std::nullopt;
	_condition_it = _tokenStream->emplace_back(CONDITION, "condition");
	_colon_it = _tokenStream->emplace_back(COLON, ":");
	_tokenStream->emplace_back(NEW_LINE, "\n");
	_rcb = _tokenStream->emplace_back(RULE_END, "}");
}

} //namespace yaramod
