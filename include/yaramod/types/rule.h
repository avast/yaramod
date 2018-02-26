/**
 * @file src/types/rule.h
 * @brief Declaration of class Rule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>
#include <vector>

#include <optional_lite/optional.hpp>

#include "yaramod/types/expression.h"
#include "yaramod/types/meta.h"
#include "yaramod/types/string.h"
#include "yaramod/types/symbol.h"
#include "yaramod/utils/trie.h"

namespace yaramod {

/**
 * Class representing YARA rule.
 */
class Rule
{
public:
	struct Location
	{
		std::string filePath;
		std::uint64_t lineNumber;
	};

	using StringsTrie = Trie<std::shared_ptr<String>>;

	/**
	 * Rule modifier for specifying if rule is
	 * either classic, global or private.
	 *
	 * @code
	 * (global|private)? rule RULE_NAME { ... }
	 * @endcode
	 */
	enum class Modifier
	{
		None,
		Global,
		Private
	};

	/// @name Constructors
	/// @{
	Rule() = default;
	explicit Rule(std::string&& name, Rule::Modifier mod, std::vector<Meta>&& metas,
			std::shared_ptr<StringsTrie>&& strings, Expression::Ptr&& condition,
			std::vector<std::string>&& tags);
	Rule(Rule&& rule) = default;
	Rule(const Rule& rule) = default;
	Rule& operator=(Rule&& rule) = default;
	/// @}

	/// @name String representation
	/// @{
	std::string getText() const;
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getName() const;
	Rule::Modifier getModifier() const;
	const std::vector<Meta>& getMetas() const;
	std::vector<const String*> getStrings() const;
	const std::shared_ptr<StringsTrie>& getStringsTrie() const;
	const Expression::Ptr& getCondition() const;
	const std::vector<std::string>& getTags() const;
	const std::shared_ptr<Symbol>& getSymbol() const;
	const Meta* getMetaWithName(const std::string& key) const;
	const Location& getLocation() const;
	/// @}

	/// @name Setter methods
	/// @{
	void setCondition(const Expression::Ptr& condition);
	void setLocation(const std::string& filePath, std::uint64_t lineNumber);
	/// @}

	/// @name Detection methods
	/// {
	bool isGlobal() const;
	bool isPrivate() const;
	/// }

	/// @name Manipulation methods
	/// @{
	void removeString(const std::string& id);
	/// @}

private:
	std::string _name; ///< Name
	Rule::Modifier _mod; ///< Modifier
	std::vector<Meta> _metas; ///< Meta information
	std::shared_ptr<StringsTrie> _strings; ///< Strings
	Expression::Ptr _condition; ///< Condition expression
	std::vector<std::string> _tags; ///< Tags
	std::shared_ptr<Symbol> _symbol; ///< Symbol representing rule
	Location _location; ///< Which file was this rule included from
};

}
