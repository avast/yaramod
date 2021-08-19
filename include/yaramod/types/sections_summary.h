/**
 * @file src/types/sections_summary.h
 * @brief Declaration of class Variable.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/types/rule.h"
#include "yaramod/types/variable.h"

namespace yaramod {

/**
 * Class representing sections summary
 * in the YARA rules.
 */
class SectionsSummary
{
public:
	/// @name Constructors
	/// @{
	SectionsSummary(std::shared_ptr<Rule::StringsTrie> default_strings, std::vector<Variable> default_variables) : _strings(default_strings), _variables(default_variables) {}
	SectionsSummary(const SectionsSummary& section_summary) = default;
	SectionsSummary(SectionsSummary&& section_summary) = default;
	/// @}

	/// @name Assignment
	/// @{
	SectionsSummary& operator=(const SectionsSummary&) = default;
	SectionsSummary& operator=(SectionsSummary&&) = default;
	/// @}

	/// @name Getter methods
	/// @{
	const std::shared_ptr<Rule::StringsTrie> getStringsTrie() const;
	const std::vector<Variable> getVariables() const;
	/// @}


	/// @name Setter methods
	/// @{
	void setStringsTrie(const std::shared_ptr<Rule::StringsTrie> strings);
	void setVariables(const std::vector<Variable> variables);
	/// @}

private:
	std::shared_ptr<Rule::StringsTrie> _strings; ///< Strings
	std::vector<Variable> _variables; ///< Variables 
};

}
