/**
 * @file src/types/yara_file.cpp
 * @brief Implementation of class YaraFile.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iterator>

#include "yaramod/types/yara_file.h"
#include "yaramod/utils/utils.h"

namespace yaramod {

/**
 * Global variables of YARA file. These would be normally defined through -d option
 * of yara tool when it is being run. We don't have such option so we define them statically
 * for the all YARA files.
 */
const std::vector<std::shared_ptr<Symbol>> YaraFile::globalVariables =
{
	// VirusTotal specific global variables
	std::make_shared<ValueSymbol>("new_file", Expression::Type::Bool),
	std::make_shared<ValueSymbol>("positives", Expression::Type::Int),
	std::make_shared<ValueSymbol>("signatures", Expression::Type::String),
	std::make_shared<ValueSymbol>("tags", Expression::Type::String),
	std::make_shared<ValueSymbol>("md5", Expression::Type::String),
	std::make_shared<ValueSymbol>("sha256", Expression::Type::String),
	std::make_shared<ValueSymbol>("imphash", Expression::Type::String),
	std::make_shared<ValueSymbol>("file_type", Expression::Type::String),
	std::make_shared<ValueSymbol>("file_name", Expression::Type::String),
	// VirusTotal specific global variables of antiviruses
	std::make_shared<ValueSymbol>("a_squared", Expression::Type::String),
	std::make_shared<ValueSymbol>("ad_aware", Expression::Type::String),
	std::make_shared<ValueSymbol>("aegislab", Expression::Type::String),
	std::make_shared<ValueSymbol>("agnitum", Expression::Type::String),
	std::make_shared<ValueSymbol>("ahnlab", Expression::Type::String),
	std::make_shared<ValueSymbol>("ahnlab_v3", Expression::Type::String),
	std::make_shared<ValueSymbol>("alibaba", Expression::Type::String),
	std::make_shared<ValueSymbol>("alyac", Expression::Type::String),
	std::make_shared<ValueSymbol>("antivir", Expression::Type::String),
	std::make_shared<ValueSymbol>("antivir7", Expression::Type::String),
	std::make_shared<ValueSymbol>("antiy_avl", Expression::Type::String),
	std::make_shared<ValueSymbol>("arcabit", Expression::Type::String),
	std::make_shared<ValueSymbol>("authentium", Expression::Type::String),
	std::make_shared<ValueSymbol>("avast", Expression::Type::String),
	std::make_shared<ValueSymbol>("avg", Expression::Type::String),
	std::make_shared<ValueSymbol>("avira", Expression::Type::String),
	std::make_shared<ValueSymbol>("avware", Expression::Type::String),
	std::make_shared<ValueSymbol>("baidu", Expression::Type::String),
	std::make_shared<ValueSymbol>("bitdefender", Expression::Type::String),
	std::make_shared<ValueSymbol>("bkav", Expression::Type::String),
	std::make_shared<ValueSymbol>("bytehero", Expression::Type::String),
	std::make_shared<ValueSymbol>("cat_quickheal", Expression::Type::String),
	std::make_shared<ValueSymbol>("clamav", Expression::Type::String),
	std::make_shared<ValueSymbol>("cmc", Expression::Type::String),
	std::make_shared<ValueSymbol>("commtouch", Expression::Type::String),
	std::make_shared<ValueSymbol>("comodo", Expression::Type::String),
	std::make_shared<ValueSymbol>("crowdstrike", Expression::Type::String),
	std::make_shared<ValueSymbol>("cyren", Expression::Type::String),
	std::make_shared<ValueSymbol>("drweb", Expression::Type::String),
	std::make_shared<ValueSymbol>("emsisoft", Expression::Type::String),
	std::make_shared<ValueSymbol>("esafe", Expression::Type::String),
	std::make_shared<ValueSymbol>("escan", Expression::Type::String),
	std::make_shared<ValueSymbol>("eset_nod32", Expression::Type::String),
	std::make_shared<ValueSymbol>("f_prot", Expression::Type::String),
	std::make_shared<ValueSymbol>("f_secure", Expression::Type::String),
	std::make_shared<ValueSymbol>("fortinet", Expression::Type::String),
	std::make_shared<ValueSymbol>("gdata", Expression::Type::String),
	std::make_shared<ValueSymbol>("ikarus", Expression::Type::String),
	std::make_shared<ValueSymbol>("invincea", Expression::Type::String),
	std::make_shared<ValueSymbol>("jiangmin", Expression::Type::String),
	std::make_shared<ValueSymbol>("k7antivirus", Expression::Type::String),
	std::make_shared<ValueSymbol>("k7gw", Expression::Type::String),
	std::make_shared<ValueSymbol>("kaspersky", Expression::Type::String),
	std::make_shared<ValueSymbol>("kingsoft", Expression::Type::String),
	std::make_shared<ValueSymbol>("malwarebytes", Expression::Type::String),
	std::make_shared<ValueSymbol>("mcafee", Expression::Type::String),
	std::make_shared<ValueSymbol>("mcafee_gw_edition", Expression::Type::String),
	std::make_shared<ValueSymbol>("microsoft", Expression::Type::String),
	std::make_shared<ValueSymbol>("microworld_escan", Expression::Type::String),
	std::make_shared<ValueSymbol>("nano_antivirus", Expression::Type::String),
	std::make_shared<ValueSymbol>("nod32", Expression::Type::String),
	std::make_shared<ValueSymbol>("norman", Expression::Type::String),
	std::make_shared<ValueSymbol>("nprotect", Expression::Type::String),
	std::make_shared<ValueSymbol>("panda", Expression::Type::String),
	std::make_shared<ValueSymbol>("pctools", Expression::Type::String),
	std::make_shared<ValueSymbol>("prevx", Expression::Type::String),
	std::make_shared<ValueSymbol>("prevx1", Expression::Type::String),
	std::make_shared<ValueSymbol>("qihoo_360", Expression::Type::String),
	std::make_shared<ValueSymbol>("rising", Expression::Type::String),
	std::make_shared<ValueSymbol>("sophos", Expression::Type::String),
	std::make_shared<ValueSymbol>("sunbelt", Expression::Type::String),
	std::make_shared<ValueSymbol>("superantispyware", Expression::Type::String),
	std::make_shared<ValueSymbol>("symantec", Expression::Type::String),
	std::make_shared<ValueSymbol>("tencent", Expression::Type::String),
	std::make_shared<ValueSymbol>("thehacker", Expression::Type::String),
	std::make_shared<ValueSymbol>("totaldefense", Expression::Type::String),
	std::make_shared<ValueSymbol>("trendmicro", Expression::Type::String),
	std::make_shared<ValueSymbol>("trendmicro_housecall", Expression::Type::String),
	std::make_shared<ValueSymbol>("vba32", Expression::Type::String),
	std::make_shared<ValueSymbol>("vipre", Expression::Type::String),
	std::make_shared<ValueSymbol>("virobot", Expression::Type::String),
	std::make_shared<ValueSymbol>("yandex", Expression::Type::String),
	std::make_shared<ValueSymbol>("zillya", Expression::Type::String),
	std::make_shared<ValueSymbol>("zoner", Expression::Type::String)
};

/**
 * Constructor.
 */
YaraFile::YaraFile() : _imports(), _rules()
{
}

/**
 * Returns the string representation of the whole YARA file.
 *
 * @return String representation.
 */
std::string YaraFile::getText() const
{
	if (!hasImports() && !hasRules())
		return std::string();

	std::ostringstream ss;
	for (const auto& module : getImports())
		ss << "import \"" << module->getName() << "\"\n";

	if (!hasRules())
		return ss.str();

	// If there are some imports, separate them with one new line from rules.
	if (hasImports())
		ss << '\n';

	for (const auto& rule : getRules())
		ss << rule->getText() << "\n\n";

	// Remove last "\n\n" from the text.
	return trim(ss.str());
}

/**
 * Adds the import of the module to the YARA file. Module needs
 * to exist and be defined in @c types/modules folder.
 *
 * @param import Imported module name.
 *
 * @return @c true if module was found, @c false otherwise.
 */
bool YaraFile::addImport(const std::string& import)
{
	auto module = Module::load(import);
	if (!module)
		return false;

	// We don't want duplicates.
	auto itr = std::find_if(_imports.begin(), _imports.end(),
			[&import](const auto& loadedModule) {
				return loadedModule->getName() == import;
			});
	if (itr != _imports.end())
		return true;

	_imports.push_back(std::move(module));
	return true;
}

/**
 * Adds the rule to the YARA file.
 *
 * @param rule Rule to add.
 */
void YaraFile::addRule(Rule&& rule)
{
	addRule(std::make_unique<Rule>(std::move(rule)));
}

/**
 * Adds the rule to the YARA file.
 *
 * @param rule Rule to add.
 */
void YaraFile::addRule(std::unique_ptr<Rule>&& rule)
{
	_rules.emplace_back(std::move(rule));
}

/**
 * Adds the rule to the YARA file.
 *
 * @param rule Rule to add.
 */
void YaraFile::addRule(const std::shared_ptr<Rule>& rule)
{
	_rules.emplace_back(rule);
}

/**
 * Adds the rules to the YARA file.
 *
 * @param rules Rules to add.
 */
void YaraFile::addRules(const std::vector<std::shared_ptr<Rule>>& rules)
{
	std::copy(rules.begin(), rules.end(), std::back_inserter(_rules));
}

/**
 * Adds the imports of the modules to the YARA file. Modules need
 * to exist and be defined in @c types/modules folder.
 *
 * @param imports Imported modules names.
 *
 * @return @c true if modules were found, @c false otherwise.
 */
bool YaraFile::addImports(const std::vector<std::string>& imports)
{
	for (const auto& module : imports)
	{
		if (!addImport(module))
			return false;
	}

	return true;
}

/**
 * Insert single rule at the specified position to the YARA file.
 *
 * @param position Position to insert rule at.
 * @param rule Rule to insert.
 */
void YaraFile::insertRule(std::size_t position, std::unique_ptr<Rule>&& rule)
{
	position = std::min(position, _rules.size());
	_rules.insert(_rules.begin() + position, std::move(rule));
}

/**
 * Insert single rule at the specified position to the YARA file.
 *
 * @param position Position to insert rule at.
 * @param rule Rule to insert.
 */
void YaraFile::insertRule(std::size_t position, const std::shared_ptr<Rule>& rule)
{
	position = std::min(position, _rules.size());
	_rules.insert(_rules.begin() + position, rule);
}

/**
 * Returns all imported modules from the YARA file in order they were added.
 *
 * @return All imported modules.
 */
const std::vector<std::shared_ptr<Module>>& YaraFile::getImports() const
{
	return _imports;
}

/**
 * Returns all rules from the YARA file in order they were added.
 *
 * @return All rules.
 */
const std::vector<std::shared_ptr<Rule>>& YaraFile::getRules() const
{
	return _rules;
}

/**
 * Finds the symbol in the YARA file. Symbol is either rule name or module identifier.
 *
 * @param name Name of the symbol to search for.
 *
 * @return Returns valid symbol if it was found, @c nullptr otherwise.
 */
std::shared_ptr<Symbol> YaraFile::findSymbol(const std::string& name) const
{
	// @todo Should rules have priority over imported modules?
	for (const auto& rule : _rules)
	{
		if (rule->getName() == name)
			return rule->getSymbol();
	}

	for (const auto& import : _imports)
	{
		if (import->getName() == name)
			return import->getStructure();
	}

	for (const auto& globalVar : YaraFile::globalVariables)
	{
		if (globalVar->getName() == name)
			return globalVar;
	}

	return nullptr;
}

/**
 * Returns whether the YARA file contains any imported modules.
 *
 * @return @c true if it contains, otherwise @c false.
 */
bool YaraFile::hasImports() const
{
	return !_imports.empty();
}

/**
 * Returns whether the YARA file contains any rules.
 *
 * @return @c true if it contains, otherwise @c false.
 */
bool YaraFile::hasRules() const
{
	return !_rules.empty();
}

}
