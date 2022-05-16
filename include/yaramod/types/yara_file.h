/**
 * @file src/types/yara_file.h
 * @brief Declaration of class YaraFile.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <vector>

#include "yaramod/types/features.h"
#include "yaramod/types/modules/module_pool.h"
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
	YaraFile(Features features = Features::AllCurrent);
	YaraFile(const std::shared_ptr<TokenStream>& tokenStream, Features features = Features::AllCurrent);
	YaraFile(YaraFile&&) noexcept;

	YaraFile& operator=(YaraFile&&) noexcept;
	/// @}

	/// @name String representation
	/// @{
	std::string getText() const;
	std::string getTextFormatted(bool withIncludes = false) const;
	/// @}

	/// @name Addition methods
	/// @{
	bool addImport(TokenIt import, ModulePool& modules);
	bool addImports(const std::vector<TokenIt>& imports, ModulePool& modules);
	void addRule(Rule&& rule, bool extractTokens = false);
	void addRule(std::unique_ptr<Rule>&& rule, bool extractTokens = false);
	void addRule(const std::shared_ptr<Rule>& rule, bool extractTokens = false);
	void addRules(const std::vector<std::shared_ptr<Rule>>& rules, bool extractTokens = false);
	void insertRule(std::size_t position, std::unique_ptr<Rule>&& rule);
	void insertRule(std::size_t position, const std::shared_ptr<Rule>& rule);
	/// @}

	/// @name Getter methods
	/// @{
	const std::vector<std::shared_ptr<Module>>& getImports() const;
	const std::vector<std::shared_ptr<Rule>>& getRules() const;
	TokenStream* getTokenStream() const;
	/// @}

	/// @name Removing methods
	/// @{
	template <typename Fn>
	void removeImports(Fn&& fn)
	{
		auto itr = std::stable_partition(_imports.begin(), _imports.end(), [&](const auto& i) { return !fn(i); });
		for (auto rem_itr = itr; rem_itr != _imports.end(); ++rem_itr)
		{
			auto rem_import = _importTable.find((*rem_itr)->getName());
			auto import_token = rem_import->second.first;
			auto bounds = _tokenStream->findBounds(import_token, TokenType::IMPORT_KEYWORD, TokenType::NEW_LINE);
			_tokenStream->erase(bounds.first, std::next(bounds.second));
			_importTable.erase(rem_import);
		}
		_imports.erase(itr, _imports.end());
	}

	template <typename Fn>
	void removeRules(Fn&& fn)
	{
		auto itr = std::stable_partition(_rules.begin(), _rules.end(), [&](const auto& i) { return !fn(i); });
		for (auto rem_itr = itr; rem_itr != _rules.end(); ++rem_itr)
		{
			_ruleTrie.remove((*rem_itr)->getName());
			_ruleTable.erase(_ruleTable.find((*rem_itr)->getName()));
			auto from = (*rem_itr)->getFirstTokenIt();
			if (from != _tokenStream->begin() && from->getType() == TokenType::NEW_LINE)
				from = std::prev(from);
			auto to = std::next((*rem_itr)->getLastTokenIt());
			auto behind = _tokenStream->erase(from, to);
			while (behind != _tokenStream->end() && behind != _tokenStream->begin() && behind->getType() == TokenType::NEW_LINE)
				behind = _tokenStream->erase(behind);
		}
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
	bool hasRule(const std::string& name) const;
	bool hasRuleWithPrefix(const std::string& prefix) const;
	std::vector<std::string> expandRulePrefixFromOrigin(const std::string& prefix, yaramod::Rule* origin) const;
	/// @}

private:
	void initializeVTSymbols();

	std::shared_ptr<TokenStream> _tokenStream; ///< tokenStream containing all the data in this Rule
	std::vector<std::shared_ptr<Module>> _imports; ///< Imported modules
	std::vector<std::shared_ptr<Rule>> _rules; ///< Rules

	std::unordered_map<std::string, std::pair<TokenIt, Module*>> _importTable;
	std::unordered_map<std::string, Rule*> _ruleTable;
	Trie<Rule*> _ruleTrie; ///< Rule trie

	Features _Features; ///< Determines which symbols are needed
	std::vector<std::shared_ptr<Symbol>> _vtSymbols; ///< Virust Total symbols
};

}
