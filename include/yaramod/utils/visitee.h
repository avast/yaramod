/**
 * @file src/utils/visitee.h
 * @brief Declaration of Visitee class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

namespace yaramod {

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
	/// @name Destructor
	/// @{
	virtual ~Visitee() {}
	/// @}

	/// @name Visitor method
	/// @{
	virtual void accept(Visitor* v) = 0;
	/// @}
};

}
