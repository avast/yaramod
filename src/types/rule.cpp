/**
 * @file src/types/rule.cpp
 * @brief Implementation of class Rule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "yaramod/types/plain_string.h"
#include "yaramod/types/rule.h"
#include "yaramod/types/symbols.h"

namespace yaramod {

/**
 * Constructor.
 *
 * @param name Name of the rule.
 * @param mod Modifier.
 * @param metas Meta information.
 * @param strings Strings.
 * @param condition Condition expression.
 * @param tags Tags.
 */
Rule::Rule()
	: _tokenStream(std::make_shared<TokenStream>())
{
	_name = _tokenStream->emplace_back(TokenType::RULE_NAME, "unknown");
}

Rule::Rule(std::string&& name, Modifier mod, std::vector<Meta>&& metas, std::shared_ptr<StringsTrie>&& strings,
		Expression::Ptr&& condition, const std::vector<std::string>& tags)
	:  _tokenStream(std::make_shared<TokenStream>())
	, _metas(std::move(metas))
	, _strings(std::move(strings))
	, _condition(std::move(condition))
	, _location({"[stream]", 0})
{
	_name = _tokenStream->emplace_back(TokenType::RULE_NAME, std::move(name));
	_symbol = std::make_shared<ValueSymbol>(_name->getPureText(), Expression::Type::Bool);

	for (const std::string& tag : tags)
	{
		TokenIt tagIt = _tokenStream->emplace_back(TokenType::TAG, tag);
		_tags.push_back(tagIt);
	}

	if (mod == Modifier::Global)
		_mod = _tokenStream->emplace_back(TokenType::GLOBAL, "global");
	else if (mod == Modifier::Private)
		_mod = _tokenStream->emplace_back(TokenType::PRIVATE, "private");
	else
		_mod = _tokenStream->emplace_back(TokenType::NONE, std::string{});
}

Rule::Rule(const std::shared_ptr<TokenStream>& tokenStream, TokenIt name, std::optional<TokenIt> mod, std::vector<Meta>&& metas, std::shared_ptr<StringsTrie>&& strings,
		Expression::Ptr&& condition, const std::vector<TokenIt>& tags)
	: _tokenStream(tokenStream)
	, _name(name)
	, _mod(mod)
	, _metas(std::move(metas))
	, _strings(std::move(strings))
	, _condition(std::move(condition))
	, _tags(tags)
	, _symbol(std::make_shared<ValueSymbol>(name->getPureText(), Expression::Type::Bool))
	, _location({"[stream]", 0})
{
}

/**
 * Returns the string representation of the YARA rule.
 *
 * @return String representation.
 */
std::string Rule::getText() const
{
	auto indent = "\t\t";
	std::ostringstream ss;

	if (isGlobal())
		ss << "global ";
	else if (isPrivate())
		ss << "private ";

	ss << "rule " << getName() << ' ';

	if (!_tags.empty())
	{
		const auto& tags = getTags();
		ss << ": ";
		std::for_each(tags.begin(), tags.end(),
				[&ss](const std::string& tag)
				{
					ss << tag << ' ';
				});
	}

	ss << "{\n";

	if (!getMetas().empty())
	{
		ss << "\tmeta:\n";
		std::for_each(getMetas().begin(), getMetas().end(),
				[&](const Meta& meta)
				{
					ss << indent << meta.getText() << '\n';
				});
	}

	auto strings = getStrings();
	if (!strings.empty())
	{
		ss << "\tstrings:\n";
		std::for_each(strings.begin(), strings.end(),
				[&](const auto& string)
				{
					ss << indent << string->getIdentifier() << " = " << string->getText() << '\n';
				});
	}
	ss << "\tcondition:\n" << indent << getCondition()->getText(indent) << "\n}";
	return ss.str();
}

/**
 * Returns the name of the YARA rule.
 *
 * @return Name.
 */
std::string Rule::getName() const
{
	return _name->getPureText();
}

/**
 * Returns the YARA rule modifier.
 *
 * @return Modifier.
 */
Rule::Modifier Rule::getModifier() const
{
	if (isGlobal())
		return Rule::Modifier::Global;
	else if (isPrivate())
		return Rule::Modifier::Private;
	else
		return Rule::Modifier::None;
}

/**
 * Returns the meta information of the YARA rule.
 *
 * @return Meta information.
 */
std::vector<Meta>& Rule::getMetas()
{
	return _metas;
}

/**
 * Returns the meta information of the YARA rule.
 *
 * @return Meta information.
 */
const std::vector<Meta>& Rule::getMetas() const
{
	return _metas;
}

/**
 * Returns the strings of the YARA rule.
 *
 * @return Strings.
 */
std::vector<const String*> Rule::getStrings() const
{
	auto allValues = _strings->getAllValues();
	std::vector<const String*> result(allValues.size());
	std::transform(allValues.begin(), allValues.end(), result.begin(),
			[](const auto& string) {
				return string.get();
			});
	return result;
}

/**
 * Returns the strings of the YARA rule.
 *
 * @return Strings.
 */
const std::shared_ptr<Rule::StringsTrie>& Rule::getStringsTrie() const
{
	return _strings;
}

/**
 * Returns the condition expression of the YARA rule.
 *
 * @return Condition expression.
 */
const Expression::Ptr& Rule::getCondition() const
{
	return _condition;
}

/**
 * Returns the tags of the YARA rule.
 *
 * @return Tags.
 */
std::vector<std::string> Rule::getTags() const
{
	std::vector<std::string> output;
	output.reserve(_tags.size());
	for (const TokenIt& item : _tags)
		output.push_back(item->getPureText());
	return output;
}

/**
 * Returns the symbols of the YARA rule.
 *
 * @return Symbol.
 */
const std::shared_ptr<Symbol>& Rule::getSymbol() const
{
	return _symbol;
}

/**
 * Returns the meta with the given key if one exists.
 *
 * @param key Key of the meta.
 *
 * @return Pointer to meta if meta with the given key exists,
 *         @c nullptr otherwise.
 */
const Meta* Rule::getMetaWithName(const std::string& key) const
{
	for (const auto& meta : _metas)
	{
		if (meta.getKey() == key)
			return &meta;
	}

	return nullptr;
}

/**
 * Returns the absolute path of a file in which this rule was located.
 * Returns "[stream]" in case this rule was parsed from input stream and not a file,
 * or if this file was created with `YaraRuleBuilder`.
 *
 * @return Location of the rule.
 */
const Rule::Location& Rule::getLocation() const
{
	return _location;
}

/**
 * Sets the name of the rule.
 *
 * @param name Name of the rule.
 */
void Rule::setName(const std::string& name)
{
	_name->setValue(name);
}

/**
 * Sets the metas of the rule.
 *
 * @param metas Metas to set.
 */
void Rule::setMetas(const std::vector<Meta>& metas)
{
	_metas = metas;
}

/**
 * Sets the tags of the rule.
 *
 * @param tags Tags to set.
 */
void Rule::setTags(const std::vector<std::string>& tags)
{
	TokenIt last;
	//delete all tags from tokenStream
	for (const TokenIt& it : _tags)
		last = _tokenStream->erase(it);
	_tags = std::vector<TokenIt>();
	// Insert new tags into TokenStream
	for (const auto& tag : tags)
	{
		TokenIt tagIt = _tokenStream->insert(last, TokenType::TAG, Literal(tag));
		_tags.push_back(tagIt);
	}
}

/**
 * Sets the condition expression of the YARA rule.
 *
 * @param condition Condition expression.
 */
void Rule::setCondition(const Expression::Ptr& condition)
{
	_condition = condition;
}

/**
 * Sets the location of the rule.
 *
 * @param location Location to set.
 */
void Rule::setLocation(const std::string& filePath, std::uint64_t lineNumber)
{
	_location = { filePath, lineNumber };
}

/**
 * Returns whether the rule has global modifier set.
 *
 * @return @c true if is global, otherwise @c false.
 */
bool Rule::isGlobal() const
{
	return _mod.has_value() && (*_mod)->getType() == TokenType::GLOBAL;
}

/**
 * Returns whether the rule has private modifier set.
 *
 * @return @c true if is private, otherwise @c false.
 */
bool Rule::isPrivate() const
{
	return _mod.has_value() && (*_mod)->getType() == TokenType::PRIVATE;
}

/**
 * Adds meta with specified name and value.
 *
 * @param name Name of the meta.
 * @param value Value of the meta.
 */
void Rule::addMeta(const std::string& name, const Literal& value)
{
	// first we need to find a proper placing for the meta within the tokenstream:
	auto metaIt = _tokenStream->find(TokenType::LCB);
	assert(metaIt != _tokenStream->end() && "Called addMeta on rule that does not contain '{' for the meta to be placed in");
	++metaIt;

	auto itKey = _tokenStream->insert(metaIt, TokenType::META_KEY, Literal(name));
	_tokenStream->insert(metaIt, TokenType::EQ, Literal(" = "));
	auto itValue = _tokenStream->insert(metaIt, TokenType::META_VALUE, value);

	_metas.emplace_back(itKey, itValue);
}

/**
 * Removes all metas with the provided name as key.
 *
 * @param name Name of the meta.
 */
void Rule::removeMetas(const std::string& name)
{
	auto newEnd = std::remove_if(_metas.begin(), _metas.end(), [name](const auto& meta) {
		return meta.getKey() == name;
	});
	_metas.erase(newEnd, _metas.end());
}

/**
 * Removes string with the given identifier.
 *
 * @param id Identifier of the string to remove.
 */
void Rule::removeString(const std::string& id)
{
	_strings->remove(id);
}

/**
 * Adds new tag at the end.
 *
 * @param tag Tag to add.
 */
void Rule::addTag(const std::string& tag)
{
	//find iterator behind tags in TokenStream
	TokenIt end = ++_tags.back();
	TokenIt newTagIt = _tokenStream->insert(end, TokenType::TAG, Literal(tag));
	_tags.push_back(newTagIt);
}

/**
 * Removes tag from the rule.
 *
 * @param tag Tag to remove.
 * @return true iff there was corresponding tag and it was removed
 */
void Rule::removeTags(const std::string& tag)
{
	auto found = std::find_if(_tags.begin(), _tags.end(), [&tag](TokenIt it){ return it->getText() == tag; });
	if (found != _tags.end())
	{
		_tokenStream->erase(*found);
		_tags.erase(found);
	}
}

void Rule::removeTags(TokenType type)
{
	auto found = std::find_if(_tags.begin(), _tags.end(), [&type](TokenIt it){ return it->getType() == type; });
	if (found != _tags.end())
	{
		_tokenStream->erase(*found);
		_tags.erase(found);
	}
}

}
