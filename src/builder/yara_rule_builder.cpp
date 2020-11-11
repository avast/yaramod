/**
 * @file src/builder/yara_rule_builder.cpp
 * @brief Implementation of class YaraRuleBuilder.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/types/expressions.h"
#include "yaramod/types/symbols.h"
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
	, _mod_private(std::nullopt)
	, _mod_global(std::nullopt)
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

	createLastString();

	if (!_condition)
	{
		_condition = std::make_shared<BoolLiteralExpression>(_tokenStream->emplace(_rcb, TokenType::BOOL_TRUE, true));
		_tokenStream->emplace(_rcb, TokenType::NEW_LINE, "\n");
	}

	auto rule = std::make_unique<Rule>(std::move(_tokenStream), std::move(_name_it), std::move(_mod_private),
		std::move(_mod_global), std::move(_metas), std::move(_strings), std::move(_variables), std::move(_condition), std::move(_tags));

	_tokenStream = std::make_shared<TokenStream>();
	resetTokens();

	_mod_private = std::nullopt;
	_mod_global = std::nullopt;
	_tags.clear();
	_metas.clear();
	_variables.clear();
	_strings = std::make_shared<Rule::StringsTrie>();

	_lastString.reset();
	_stringMods.clear();
	_stringModsTokens->clear();

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
	if (name.empty())
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
	if (mod == Rule::Modifier::Global)
	{
		if (_mod_global != std::nullopt)
			throw RuleBuilderError("Error: Rule already has a global modifier.");
		_mod_global = _tokenStream->emplace(_rule_it, TokenType::GLOBAL, "global");
	}
	else if (mod == Rule::Modifier::Private)
	{
		if (_mod_private != std::nullopt)
			throw RuleBuilderError("Error: Rule already has a private modifier.");
		_mod_private = _tokenStream->emplace(_rule_it, TokenType::PRIVATE, "private");
	}
	else
	{
		assert(mod == Rule::Modifier::None);
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
	if (tag.empty())
		throw RuleBuilderError("Error: tag must be non-empty.");
	if (_tags.empty())
		_tokenStream->emplace(_lcb, TokenType::COLON, ":");
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
	if (comment.empty())
		throw RuleBuilderError("Error: comment must be non-empty.");
	TokenIt insert_before = _mod_private.value_or(_mod_global.value_or(_rule_it));
	std::stringstream ss;
	if (multiline)
	{
		ss << "/* " << comment << " */";
		_tokenStream->emplace(insert_before, TokenType::COMMENT, ss.str());
	}
	else
	{
		if (comment.find('\n') != std::string::npos)
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
	if (key.empty())
		throw RuleBuilderError("Error: String-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_variables_it.value_or(_condition_it));

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, TokenType::META, "meta");
		_tokenStream->emplace(insert_before, TokenType::COLON_BEFORE_NEWLINE, ":");
		_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");
	}

	auto itKey = _tokenStream->emplace(insert_before, TokenType::META_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::META_VALUE, escapeString(value));
	itValue->markEscaped();
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
	if (key.empty())
		throw RuleBuilderError("Error: Int-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_variables_it.value_or(_condition_it));

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, TokenType::META, "meta");
		_tokenStream->emplace(insert_before, TokenType::COLON_BEFORE_NEWLINE, ":");
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
	if (key.empty())
		throw RuleBuilderError("Error: UInt-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_variables_it.value_or(_condition_it));

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, TokenType::META, "meta");
		_tokenStream->emplace(insert_before, TokenType::COLON_BEFORE_NEWLINE, ":");
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
	if (key.empty())
		throw RuleBuilderError("Error: HexInt-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_variables_it.value_or(_condition_it));

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, TokenType::META, "meta");
		_tokenStream->emplace(insert_before, TokenType::COLON_BEFORE_NEWLINE, ":");
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
	if (key.empty())
		throw RuleBuilderError("Error: Bool-Meta key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_variables_it.value_or(_condition_it));

	if (_metas.empty())
	{
		_tokenStream->emplace(insert_before, TokenType::META, "meta");
		_tokenStream->emplace(insert_before, TokenType::COLON_BEFORE_NEWLINE, ":");
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
 * Adds a string variable to a rule.
 *
 * @param key Key of variable.
 * @param value String value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withStringVariable(const std::string& key, const std::string& value)
{
	if (key.empty())
		throw RuleBuilderError("Error: String-Variable key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (!_variables_it.has_value())
		initializeVariables();

	auto itKey = _tokenStream->emplace(insert_before, TokenType::VARIABLE_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::STRING_LITERAL, escapeString(value));
	itValue->markEscaped();
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

	auto expr = std::make_shared<StringLiteralExpression>(itValue);
	expr->setType(Expression::Type::String);
	_variables.emplace_back(itKey, expr);

	return *this;
}

/**
 * Adds an integer variable to a rule.
 *
 * @param key Key of variable.
 * @param value Integer value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withIntVariable(const std::string& key, std::int64_t value)
{
	if (key.empty())
		throw RuleBuilderError("Error: Int-Variable key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (!_variables_it.has_value())
		initializeVariables();

	auto itKey = _tokenStream->emplace(insert_before, TokenType::VARIABLE_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::INTEGER, value);
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

	auto expr = std::make_shared<IntLiteralExpression>(itValue);
	expr->setType(Expression::Type::Int);
	_variables.emplace_back(itKey, expr);
	return *this;
}

/**
 * Adds an unsigned integer variable to a rule.
 *
 * @param key Key of variable.
 * @param value Unsigned integer value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withUIntVariable(const std::string& key, std::uint64_t value)
{
	if (key.empty())
		throw RuleBuilderError("Error: UInt-Variable key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (!_variables_it.has_value())
		initializeVariables();

	auto itKey = _tokenStream->emplace(insert_before, TokenType::VARIABLE_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::INTEGER, value);
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

	auto expr = std::make_shared<IntLiteralExpression>(itValue);
	expr->setType(Expression::Type::Int);
	_variables.emplace_back(itKey, expr);
	return *this;
}

/**
 * Adds a hexadecimal integer variable to a rule.
 *
 * @param key Key of variable.
 * @param value Hexadecimal integer value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withHexIntVariable(const std::string& key, std::uint64_t value)
{
	if (key.empty())
		throw RuleBuilderError("Error: HexInt-Variable key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (!_variables_it.has_value())
		initializeVariables();

	auto itKey = _tokenStream->emplace(insert_before, TokenType::VARIABLE_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::INTEGER, value, std::make_optional<std::string>(numToStr(value, std::hex, true)));
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

	auto expr = std::make_shared<IntLiteralExpression>(itValue);
	expr->setType(Expression::Type::Int);
	_variables.emplace_back(itKey, expr);
	return *this;
}

/**
 * Adds a boolean variable to a rule.
 *
 * @param key Key of Variable.
 * @param value Boolean value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withDoubleVariable(const std::string& key, double value)
{
	if (key.empty())
		throw RuleBuilderError("Error: Bool-Variable key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (!_variables_it.has_value())
		initializeVariables();

	auto itKey = _tokenStream->emplace(insert_before, TokenType::VARIABLE_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::DOUBLE, value);
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

	auto expr = std::make_shared<DoubleLiteralExpression>(itValue);
	expr->setType(Expression::Type::Float);
	_variables.emplace_back(itKey, expr);
	return *this;
}

/**
 * Adds a boolean variable to a rule.
 *
 * @param key Key of Variable.
 * @param value Boolean value.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withBoolVariable(const std::string& key, bool value)
{
	if (key.empty())
		throw RuleBuilderError("Error: Bool-Variable key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (!_variables_it.has_value())
		initializeVariables();

	auto itKey = _tokenStream->emplace(insert_before, TokenType::VARIABLE_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, value ? TokenType::BOOL_TRUE : TokenType::BOOL_FALSE, value);
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

	auto expr = std::make_shared<BoolLiteralExpression>(itValue);
	expr->setType(Expression::Type::Bool);
	_variables.emplace_back(itKey, expr);
	return *this;
}

/**
 * Adds a struct variable to a rule.
 *
 * @param key Key of Variable.
 * @param value Struct object identifier.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withStructVariable(const std::string& key, const std::string& identifier)
{
	if (key.empty())
		throw RuleBuilderError("Error: Struct-Variable key must be non-empty.");

	TokenIt insert_before = _strings_it.value_or(_condition_it);

	if (!_variables_it.has_value())
		initializeVariables();

	auto itKey = _tokenStream->emplace(insert_before, TokenType::VARIABLE_KEY, key);
	_tokenStream->emplace(insert_before, TokenType::ASSIGN, "=");
	auto itValue = _tokenStream->emplace(insert_before, TokenType::ID, identifier);
	_tokenStream->emplace(insert_before, TokenType::NEW_LINE, "\n");

	const std::shared_ptr<Symbol>& symbol = std::make_shared<StructureSymbol>(identifier);
	itValue->setValue(symbol);

	auto expr = std::make_shared<IdExpression>(itValue);
	_variables.emplace_back(itKey, expr);
	return *this;
}

/**
 * Adds a plain string to a rule.
 *
 * @param id Identifier of the string.
 * @param value Plain string text.
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withPlainString(const std::string& id, const std::string& value)
{
	createLastString();

	if (id.empty() || value.empty())
		throw RuleBuilderError("Error: Plain string id and value must be non-empty.");

	if (!_strings_it.has_value())
		initializeStrings();

	auto stringTokenStream = std::make_shared<TokenStream>();
	auto plainString = std::make_shared<PlainString>(stringTokenStream, escapeString(value));
	plainString->setIdentifier(id);

	_strings->insert(id, std::static_pointer_cast<String>(plainString));

	_lastString = plainString;
	_stringMods.clear();
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
	createLastString();

	if (id.empty() || hexString->empty())
		throw RuleBuilderError("Error: Hex string id and value must be non-empty.");

	if (!_strings_it.has_value())
		initializeStrings();

	hexString->setIdentifier(id);

	_strings->insert(id, std::static_pointer_cast<String>(hexString));

	_lastString = hexString;
	_stringMods.clear();
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
 *
 * @return Builder.
 */
YaraRuleBuilder& YaraRuleBuilder::withRegexp(const std::string& id, const std::string& value, const std::string& suffixMods)
{
	createLastString();

	if (id.empty() || value.empty())
		throw RuleBuilderError("Error: Regexp id and value must be non-empty.");

	if (!_strings_it.has_value())
		initializeStrings();

	auto stringTokenStream = std::make_shared<TokenStream>();
	auto regexp = std::make_shared<Regexp>(stringTokenStream, std::make_shared<RegexpText>(value));
	regexp->setIdentifier(id);
	regexp->setSuffixModifiers(suffixMods);

	_strings->insert(id, std::static_pointer_cast<String>(regexp));

	_lastString = regexp;
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
	_tokenStream->moveAppend(_rcb, _condition->getTokenStream());
	_tokenStream->emplace(_rcb, TokenType::NEW_LINE, "\n");
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
	_tokenStream->moveAppend(_rcb, _condition->getTokenStream());
	_tokenStream->emplace(_rcb, TokenType::NEW_LINE, "\n");
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::ascii()
{
	auto token = _stringModsTokens->emplace_back(TokenType::ASCII, "ascii");
	_stringMods.push_back(std::make_shared<AsciiStringModifier>(token));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::wide()
{
	auto token = _stringModsTokens->emplace_back(TokenType::WIDE, "wide");
	_stringMods.push_back(std::make_shared<WideStringModifier>(token));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::nocase()
{
	auto token = _stringModsTokens->emplace_back(TokenType::NOCASE, "nocase");
	_stringMods.push_back(std::make_shared<NocaseStringModifier>(token));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::fullword()
{
	auto token = _stringModsTokens->emplace_back(TokenType::FULLWORD, "fullword");
	_stringMods.push_back(std::make_shared<FullwordStringModifier>(token));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::private_()
{
	auto token = _stringModsTokens->emplace_back(TokenType::PRIVATE_STRING_MODIFIER, "private");
	_stringMods.push_back(std::make_shared<PrivateStringModifier>(token));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::xor_()
{
	auto token = _stringModsTokens->emplace_back(TokenType::XOR, "xor");
	_stringMods.push_back(std::make_shared<XorStringModifier>(token));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::xor_(std::uint64_t key)
{
	auto firstToken = _stringModsTokens->emplace_back(TokenType::XOR, "xor");
	_stringModsTokens->emplace_back(TokenType::LP, "(");
	_stringModsTokens->emplace_back(TokenType::INTEGER, key, numToStr(key));
	auto lastToken = _stringModsTokens->emplace_back(TokenType::RP, ")");
	_stringMods.push_back(std::make_shared<XorStringModifier>(firstToken, lastToken, key));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::xor_(std::uint64_t low, std::uint64_t high)
{
	auto firstToken = _stringModsTokens->emplace_back(TokenType::XOR, "xor");
	_stringModsTokens->emplace_back(TokenType::LP, "(");
	_stringModsTokens->emplace_back(TokenType::INTEGER, low, numToStr(low));
	_stringModsTokens->emplace_back(TokenType::MINUS, "-");
	_stringModsTokens->emplace_back(TokenType::INTEGER, high, numToStr(high));
	auto lastToken = _stringModsTokens->emplace_back(TokenType::RP, ")");
	_stringMods.push_back(std::make_shared<XorStringModifier>(firstToken, lastToken, low, high));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::base64()
{
	auto token = _stringModsTokens->emplace_back(TokenType::BASE64, "base64");
	_stringMods.push_back(std::make_shared<Base64StringModifier>(token));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::base64(const std::string& alphabet)
{
	auto escapedAlphabet = escapeString(alphabet);
	auto firstToken = _stringModsTokens->emplace_back(TokenType::BASE64, "base64");
	_stringModsTokens->emplace_back(TokenType::LP, "(");
	_stringModsTokens->emplace_back(TokenType::STRING_LITERAL, escapedAlphabet, escapedAlphabet);
	auto lastToken = _stringModsTokens->emplace_back(TokenType::RP, ")");
	_stringMods.push_back(std::make_shared<Base64StringModifier>(firstToken, lastToken, alphabet));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::base64wide()
{
	auto token = _stringModsTokens->emplace_back(TokenType::BASE64WIDE, "base64wide");
	_stringMods.push_back(std::make_shared<Base64WideStringModifier>(token));
	return *this;
}

YaraRuleBuilder& YaraRuleBuilder::base64wide(const std::string& alphabet)
{
	auto escapedAlphabet = escapeString(alphabet);
	auto firstToken = _stringModsTokens->emplace_back(TokenType::BASE64WIDE, "base64wide");
	_stringModsTokens->emplace_back(TokenType::LP, "(");
	_stringModsTokens->emplace_back(TokenType::STRING_LITERAL, escapedAlphabet, escapedAlphabet);
	auto lastToken = _stringModsTokens->emplace_back(TokenType::RP, ")");
	_stringMods.push_back(std::make_shared<Base64WideStringModifier>(firstToken, lastToken, alphabet));
	return *this;
}

void YaraRuleBuilder::initializeStrings()
{
	auto before = _variables_it.value_or(_condition_it);

	_strings_it = _tokenStream->emplace(before, TokenType::STRINGS, "strings");
	_tokenStream->emplace(before, TokenType::COLON_BEFORE_NEWLINE, ":");
	_tokenStream->emplace(before, TokenType::NEW_LINE, "\n");
}

void YaraRuleBuilder::resetTokens()
{
	_rule_it = _tokenStream->emplace_back(TokenType::RULE, "rule");
	_name_it = _tokenStream->emplace_back(TokenType::RULE_NAME, "unknown");
	_lcb = _tokenStream->emplace_back(TokenType::RULE_BEGIN, "{");
	_tokenStream->emplace_back(TokenType::NEW_LINE, "\n");
	_strings_it = std::nullopt;
	_variables_it = std::nullopt;
	_condition_it = _tokenStream->emplace_back(TokenType::CONDITION, "condition");
	_colon_it = _tokenStream->emplace_back(TokenType::COLON_BEFORE_NEWLINE, ":");
	_tokenStream->emplace_back(TokenType::NEW_LINE, "\n");
	_rcb = _tokenStream->emplace_back(TokenType::RULE_END, "}");

	_stringModsTokens = std::make_shared<TokenStream>();
}

void YaraRuleBuilder::createLastString()
{
	if (_lastString)
	{
		_lastString->setModifiersWithTokens(_stringMods, _stringModsTokens, true);
		_tokenStream->moveAppend(_condition_it, _lastString->getTokenStream().get());
		_tokenStream->emplace(_condition_it, TokenType::NEW_LINE, "\n");
		_lastString.reset();
		_stringMods.clear();
	}
}

void YaraRuleBuilder::initializeVariables()
{
	_variables_it = _tokenStream->emplace(_condition_it, TokenType::VARIABLES, "variables");
	_tokenStream->emplace(_condition_it, TokenType::COLON_BEFORE_NEWLINE, ":");
	_tokenStream->emplace(_condition_it, TokenType::NEW_LINE, "\n");
}

} //namespace yaramod
