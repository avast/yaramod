/**
 * @file src/examples/simplify_bools/main.cpp
 * @brief Implementation of main for boolean simplifier.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <string>
#include <vector>

#include <yaramod/yaramod.h>

#include "bool_simplifier.h"
#include "interesting_rule_inserter.h"

int main(int argc, char* argv[])
{
	std::vector<std::string> args(argv + 1, argv + argc);
	if (args.size() != 1)
	{
		std::cout << "Usage: dump-rules-ast YARA_FILE" << std::endl;
		return 1;
	}

	//BoolSimplifier simplifier;

	yaramod::Yaramod yaramod;

	auto yaraFile = yaramod.parseFile(args[0], yaramod::ParserMode::IncludeGuarded);

	if (yaraFile)
	{
		std::cout << yaraFile->getText() << std::endl;
		std::cout << yaraFile->getTextFormatted() << std::endl;
	}


	//auto yaraFile = yaramod.parseFile(args[0]);
	//for (auto& rule : yaraFile->getRules())
	//{
	//	if (rule->getName() == "installcorelike_known_named_objects")
	//		rule->setCondition(yaramod::boolVal(false).get());

	//	std::cout << "==== RULE: " << rule->getName() << std::endl;
	//	std::cout << "==== BEFORE" << std::endl;
	//	std::cout << rule->getText() << std::endl;
	//	auto result = simplifier.modify(rule->getCondition(), std::make_shared<yaramod::BoolLiteralExpression>(false));
	//	rule->setCondition(result);
	//	std::cout << "==== AFTER" << std::endl;
	//	std::cout << rule->getText() << std::endl;
	//}

	//InterestingRuleInserter inserter;
	//inserter.insert_interesting_rule(yaraFile.get());
	//std::cout << "==== INTERESTING" << std::endl;
	//std::cout << yaraFile->getText() << std::endl;
}
