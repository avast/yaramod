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
const std::map<std::string name, Expression::Type type> globalVariables
{
   std::make_pair("new_file", Expression::Type::Bool),
   std::make_pair("positives", Expression::Type::Int),
   std::make_pair("signatures", Expression::Type::String),
   std::make_pair("tags", Expression::Type::String),
   std::make_pair("md5", Expression::Type::String),
   std::make_pair("sha256", Expression::Type::String),
   std::make_pair("imphash", Expression::Type::String),
   std::make_pair("file_type", Expression::Type::String),
   std::make_pair("file_name", Expression::Type::String),
   // VirusTotal specific global variables of antiviruses
   std::make_pair("a_squared", Expression::Type::String),
   std::make_pair("ad_aware", Expression::Type::String),
   std::make_pair("aegislab", Expression::Type::String),
   std::make_pair("agnitum", Expression::Type::String),
   std::make_pair("ahnlab", Expression::Type::String),
   std::make_pair("ahnlab_v3", Expression::Type::String),
   std::make_pair("alibaba", Expression::Type::String),
   std::make_pair("alyac", Expression::Type::String),
   std::make_pair("antivir", Expression::Type::String),
   std::make_pair("antivir7", Expression::Type::String),
   std::make_pair("antiy_avl", Expression::Type::String),
   std::make_pair("arcabit", Expression::Type::String),
   std::make_pair("authentium", Expression::Type::String),
   std::make_pair("avast", Expression::Type::String),
   std::make_pair("avg", Expression::Type::String),
   std::make_pair("avira", Expression::Type::String),
   std::make_pair("avware", Expression::Type::String),
   std::make_pair("baidu", Expression::Type::String),
   std::make_pair("bitdefender", Expression::Type::String),
   std::make_pair("bkav", Expression::Type::String),
   std::make_pair("bytehero", Expression::Type::String),
   std::make_pair("cat_quickheal", Expression::Type::String),
   std::make_pair("clamav", Expression::Type::String),
   std::make_pair("cmc", Expression::Type::String),
   std::make_pair("commtouch", Expression::Type::String),
   std::make_pair("comodo", Expression::Type::String),
   std::make_pair("crowdstrike", Expression::Type::String),
   std::make_pair("cyren", Expression::Type::String),
   std::make_pair("drweb", Expression::Type::String),
   std::make_pair("emsisoft", Expression::Type::String),
   std::make_pair("esafe", Expression::Type::String),
   std::make_pair("escan", Expression::Type::String),
   std::make_pair("eset_nod32", Expression::Type::String),
   std::make_pair("f_prot", Expression::Type::String),
   std::make_pair("f_secure", Expression::Type::String),
   std::make_pair("fortinet", Expression::Type::String),
   std::make_pair("gdata", Expression::Type::String),
   std::make_pair("ikarus", Expression::Type::String),
   std::make_pair("invincea", Expression::Type::String),
   std::make_pair("jiangmin", Expression::Type::String),
   std::make_pair("k7antivirus", Expression::Type::String),
   std::make_pair("k7gw", Expression::Type::String),
   std::make_pair("kaspersky", Expression::Type::String),
   std::make_pair("kingsoft", Expression::Type::String),
   std::make_pair("malwarebytes", Expression::Type::String),
   std::make_pair("mcafee", Expression::Type::String),
   std::make_pair("mcafee_gw_edition", Expression::Type::String),
   std::make_pair("microsoft", Expression::Type::String),
   std::make_pair("microworld_escan", Expression::Type::String),
   std::make_pair("nano_antivirus", Expression::Type::String),
   std::make_pair("nod32", Expression::Type::String),
   std::make_pair("norman", Expression::Type::String),
   std::make_pair("nprotect", Expression::Type::String),
   std::make_pair("panda", Expression::Type::String),
   std::make_pair("pctools", Expression::Type::String),
   std::make_pair("prevx", Expression::Type::String),
   std::make_pair("prevx1", Expression::Type::String),
   std::make_pair("qihoo_360", Expression::Type::String),
   std::make_pair("rising", Expression::Type::String),
   std::make_pair("sophos", Expression::Type::String),
   std::make_pair("sunbelt", Expression::Type::String),
   std::make_pair("superantispyware", Expression::Type::String),
   std::make_pair("symantec", Expression::Type::String),
   std::make_pair("tencent", Expression::Type::String),
   std::make_pair("thehacker", Expression::Type::String),
   std::make_pair("totaldefense", Expression::Type::String),
   std::make_pair("trendmicro", Expression::Type::String),
   std::make_pair("trendmicro_housecall", Expression::Type::String),
   std::make_pair("vba32", Expression::Type::String),
   std::make_pair("vipre", Expression::Type::String),
   std::make_pair("virobot", Expression::Type::String),
   std::make_pair("yandex", Expression::Type::String),
   std::make_pair("zillya", Expression::Type::String),
   std::make_pair("zoner", Expression::Type::String)
}

/**
 * Constructor.
 */
YaraFile::YaraFile()
   : YaraFile(std::move(std::make_shared<TokenStream>()))
{
   std::cout << "Constructor YaraFile called: new TokenStream created" << std::endl;
}

YaraFile::YaraFile(std::shared_ptr<TokenStream> tokenStream)
   : _tokenStream(std::move(tokenStream))
   , _imports()
   , _rules()
{
   std::cout << "Constructor YaraFile called with TokenStream '" << *_tokenStream << "'" << std::endl;
}

/**
 * Returns the string representation of the whole YARA file.
 *
 * @return String representation.
 */
std::string YaraFile::getText() const
{
   std::cout << "YaraFile getText tokenStream: " << "'" << *_tokenStream << "'" << std::endl;
   std::cout << "getText1" << std::endl;
   if (!hasImports() && !hasRules())
      return std::string();

   std::cout << "getText1" << std::endl;
   std::ostringstream ss;
   for (const auto& module : getImports())
      ss << "import \"" << module->getName() << "\"\n";

   std::cout << "getText1" << std::endl;
   if (!hasRules())
      return ss.str();

   // If there are some imports, separate them with one new line from rules.
   std::cout << "getText1" << std::endl;
   if (hasImports())
      ss << '\n';

   std::cout << "getText1" << std::endl;
   for (const auto& rule : getRules())
      ss << rule->getText() << "\n\n";

   std::cout << "getText1" << std::endl;
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
bool YaraFile::addImport(TokenIt import)
{
   auto module = Module::load(import->getPureText());
   if (!module)
      return false;

   // We don't want duplicates.
   auto itr = std::find_if(_imports.begin(), _imports.end(),
         [&import](const auto& loadedModule) {
            return loadedModule->getName() == import->getPureText();
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
bool YaraFile::addImports(const std::vector<TokenIt>& imports)
{
   for (const TokenIt& module : imports)
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
 * Finds the symbol in the YARA file. Symbol is either rule name or module identifier or a global var.
 *
 * @param name Name of the symbol to search for.
 *
 * @return Returns valid symbol if it was found, @c nullptr otherwise.
 */
std::shared_ptr<Symbol> YaraFile::findSymbol(const std::string& name, TokenStream* ts) const
{
   // @todo Should rules have priority over imported modules?
   std::shared_ptr<Symbol> output = findRule(name);
   if(output)
      return output;
   output = findImport(name);
   if(output)
      return output;
   return findAndEmplaceGlobalVariable(ts, name);
}


std::shared_ptr<Symbol> YaraFile::findRule(const std::string& name) const
{
   for (const auto& rule : _rules)
      if (rule->getName() == name)
         return rule->getSymbol();
   return nullptr;
}

std::shared_ptr<Symbol> YaraFile::findImport(const std::string& name) const
{
   for (const auto& import : _imports)
      if (import->getName() == name)
         return import->getStructure();
   return nullptr;
}

std::shared_ptr<Symbol> findAndEmplaceGlobalVariable(TokenStream* ts, const std::string& name)
{
   assert(ts != nullptr);
   auto it = globalVariables.find(name);
   if(it == globalVariables.end())
      return nullptr;
   else
   {
      TokenIt symbol_name = ts->emplace_back(TokenType::GLOBAL_VARIABLE_NAME, name);
      return std::make_shared<ValueSymbol>(symbol_name, it->second);
   }
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
