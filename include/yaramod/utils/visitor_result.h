/**
 * @file src/utils/visitor_result.h
 * @brief Declaration of Visitor result and its components.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>

#include <variant/variant.hpp>

namespace yaramod {

class Expression;

/**
 * Represents the action that visitor should preform with the visited expression.
 */
enum class VisitAction
{
	Delete
};

using VisitResult = mpark::variant<std::shared_ptr<Expression>, VisitAction>;

}
