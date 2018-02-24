/**
 * @file src/types/ast_node.h
 * @brief Declaration of AST node for expressions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <optional_lite/optional.hpp>

#include "yaramod/types/expression.h"
#include "yaramod/utils/visitee.h"

namespace yaramod {

/**
 * This class represents single AST node in AST of a rule condition.
 * It encapsulates yaramod::Expression object. The reason for having this
 * class and not directly creating AST out of expression objects is that
 * we can directly modify AST node in yaramod::ModifyingVisitor::modify.
 * It is also more clear what we do if we return `makeASTNode<T>(...)`
 * rather than just `std;:make_shared<Expression>(...)`.
 */
class ASTNode
{
public:
	using Ptr = std::shared_ptr<ASTNode>;

	ASTNode(const std::shared_ptr<Expression>& expr) : _expr(expr) {}
	ASTNode(std::shared_ptr<Expression>&& expr) : _expr(std::move(expr)) {}

	const std::shared_ptr<Expression>& getExpression() const { return _expr; }

	void setExpression(const std::shared_ptr<Expression>& expr) { _expr = expr; }
	void setExpression(std::shared_ptr<Expression>&& expr) { _expr = std::move(expr); }

	Visitee::ReturnType accept(Visitor* v)
	{
		return _expr->accept(v);
	}

private:
	std::shared_ptr<Expression> _expr;
};

/**
 * Creates AST node with expression of specified type and passes
 * provided arguments to its constructor.
 *
 * @tparam T Expression type.
 * @tparam Args Constructor argument types.
 *
 * @param args Constructor arguments.
 *
 * @return New AST node.
 */
template <typename Expr, typename... Args>
decltype(auto) makeASTNode(Args&&... args)
{
	return std::make_shared<ASTNode>(std::make_shared<Expr>(std::forward<Args>(args)...));
}

}
