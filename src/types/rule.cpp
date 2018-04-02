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
Rule::Rule(std::string&& name, Modifier mod, std::vector<Meta>&& metas, std::shared_ptr<StringsTrie>&& strings,
		Expression::Ptr&& condition, std::vector<std::string>&& tags)
	: _name(std::move(name)), _mod(mod), _metas(std::move(metas)), _strings(std::move(strings)),
		_condition(std::move(condition)), _tags(std::move(tags)), _symbol(std::make_shared<ValueSymbol>(_name, Expression::Type::Bool)),
		_location({"[stream]", 0})
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

	if (!getTags().empty())
	{
		ss << ": ";
		std::for_each(getTags().begin(), getTags().end(),
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
const std::string& Rule::getName() const
{
	return _name;
}

/**
 * Returns the YARA rule modifier.
 *
 * @return Modifier.
 */
Rule::Modifier Rule::getModifier() const
{
	return _mod;
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
const std::vector<std::string>& Rule::getTags() const
{
	return _tags;
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
	return _mod == Rule::Modifier::Global;
}

/**
 * Returns whether the rule has private modifier set.
 *
 * @return @c true if is private, otherwise @c false.
 */
bool Rule::isPrivate() const
{
	return _mod == Rule::Modifier::Private;
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

}
