/**
 * @file src/types/sections_summary.cpp
 * @brief Implementation of class SectionsSummary.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "yaramod/types/sections_summary.h"
#include "yaramod/types/rule.h"
#include "yaramod/types/variable.h"

namespace yaramod {

/**
 * Returns StringsTrie.
 *
 * @return StringsTrie.
 */
const std::shared_ptr<Rule::StringsTrie> SectionsSummary::getStringsTrie() const
{
	return std::move(_strings);
}

/**
 * Returns vector of variables.
 *
 * @return Vector of variables.
 */
const std::vector<Variable> SectionsSummary::getVariables() const
{
	return _variables;
}

/**
 * Set the StringsTrie.
 *
 * @param key Key.
 */
void SectionsSummary::setStringsTrie(const std::shared_ptr<Rule::StringsTrie> strings)
{
    _is_strings_set = true;
	_strings = std::move(strings);
}

/**
 * Set the vector of variables.
 *
 * @param value Value.
 */
void SectionsSummary::setVariables(const std::vector<Variable> variables)
{
    _is_variables_set = true;
	_variables = variables;
}

}
