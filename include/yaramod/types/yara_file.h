/**
 * @file src/types/yara_file.h
 * @brief Declaration of class YaraFile.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <vector>

#include "yaramod/types/modules/module.h"
#include "yaramod/types/rule.h"

namespace yaramod {

/**
 * Class representing YARA file with all the imports and
 * rules it contains.
 */
class YaraFile
{
public:
	/// @name Constructors
	/// @{
	YaraFile();
	YaraFile(YaraFile&&) noexcept = default;
	/// @}

	/// @name String representation
	/// @{
	std::string getText() const;
	/// @}

	/// @name Addition methods
	/// @{
	bool addImport(const std::string& import);
	void addRule(Rule&& rule);
	void addRule(std::unique_ptr<Rule>&& rule);
	void addRule(const std::shared_ptr<Rule>& rule);
	void addRules(const std::vector<std::shared_ptr<Rule>>& rules);
	bool addImports(const std::vector<std::string>& imports);
	void insertRule(std::size_t position, std::unique_ptr<Rule>&& rule);
	void insertRule(std::size_t position, const std::shared_ptr<Rule>& rule);
	/// @}

	/// @name Getter methods
	/// @{
	const std::vector<std::shared_ptr<Module>>& getImports() const;
	const std::vector<std::shared_ptr<Rule>>& getRules() const;
	/// @}

	/// @name Removing methods
	/// @{
	template <typename Fn>
	void removeImports(Fn&& fn)
	{
		auto itr = std::remove_if(_imports.begin(), _imports.end(), fn);
		_imports.erase(itr, _imports.end());
	}

	template <typename Fn>
	void removeRules(Fn&& fn)
	{
		auto itr = std::remove_if(_rules.begin(), _rules.end(), fn);
		_rules.erase(itr, _rules.end());
	}
	/// @}

	/// @name Symbol methods
	/// @{
	std::shared_ptr<Symbol> findSymbol(const std::string& name) const;
	/// @}

	/// @name Detection methods
	/// @{
	bool hasImports() const;
	bool hasRules() const;
	/// @}

private:
	std::vector<std::shared_ptr<Module>> _imports; ///< Imported modules
	std::vector<std::shared_ptr<Rule>> _rules; ///< Rules

	static const std::vector<std::shared_ptr<Symbol>> globalVariables; ///< Global variables
};

}
