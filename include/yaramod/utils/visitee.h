/**
 * @file src/utils/visitee.h
 * @brief Declaration of Visitee class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>

#include <optional_lite/optional.hpp>
#include <variant/variant.hpp>

namespace yaramod {

class ASTNode;
class Visitor;

/**
 * Class representing visited entity by @c Visitor. This class should
 * be inherited by every class that wants to be visit. Method @c accept
 * should be implemented just as this line of code.
 *
 * @code
 * v->visit(this);
 * @endcode
 */
class Visitee
{
public:
	/**
	 * Indicates action that should be performed by visitor on visitee.
	 */
	enum class Action
	{
		Delete
	};

	using ReturnType = mpark::variant<std::shared_ptr<ASTNode>, Visitee::Action>;

	/// @name Destructor
	/// @{
	virtual ~Visitee() {}
	/// @}

	/// @name Visitor method
	/// @{
	virtual Visitee::ReturnType accept(Visitor* v) = 0;
	/// @}
};

}
