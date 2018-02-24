/**
 * @file src/utils/modifying_visitor.h
 * @brief Declaration of ModifyingVisitor class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/types/expressions.h"
#include "yaramod/utils/visitor.h"

namespace yaramod {

/**
 * Abstract class representing modifying visitor of condition expression in YARA files.
 * It is capable of modifying AST. Each visit() method has return value of
 * @c Visitee::ReturnType what is just an alis for `optional<std::shared_ptr<ASTNode>>`.
 * There are 3 possible values you can return in order to control the behavior of the visitor:
 *
 * 1. nullopt - Returning unset optional value means keeping the node as it is and not modifying it all.
 * 2. nullptr - Returning `nullptr` value inside of optional means delete this AST node.
 * 3. ASTNode - Returning valid instance of ASTNode means replace this AST node with the one I returned you.
 *
 * You can of course override this behavior by providing your own implementaion of each visit()
 * method but this is the default one. If you want to override some part of the logic but fall-back
 * to the default handling if the AST node does not meet your criteria, you can do that by calling
 * defaultHandler() and passing it the current expression together with results from visited child nodes.
 * Not every type of expression has defaultHandler() and you will get compilation error if you
 * try to call one if it does not exist.
 */
class ModifyingVisitor : public Visitor
{
public:
	void modify(ASTNode::Ptr& expr)
	{
		if (auto result = expr->accept(this))
			expr->setExpression(result.value() ? result.value()->getExpression() : nullptr);
	}

	/// @name Visit methods
	/// @{
	virtual Visitee::ReturnType visit(StringExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(StringWildcardExpression*) override { return {}; }

	virtual Visitee::ReturnType visit(StringAtExpression* expr) override
	{
		auto atExpr = expr->getAtExpression()->accept(this);
		return defaultHandler(expr, atExpr);
	}

	virtual Visitee::ReturnType visit(StringInRangeExpression* expr) override
	{
		auto rangeExpr = expr->getRangeExpression()->accept(this);
		return defaultHandler(expr, rangeExpr);
	}

	virtual Visitee::ReturnType visit(StringCountExpression*) override { return {}; }

	virtual Visitee::ReturnType visit(StringOffsetExpression* expr) override
	{
		if (expr->getIndexExpression())
		{
			auto indexExpr = expr->getIndexExpression()->accept(this);
			return defaultHandler(expr, indexExpr);
		}

		return defaultHandler(expr, {});
	}

	virtual Visitee::ReturnType visit(StringLengthExpression* expr) override
	{
		if (expr->getIndexExpression())
		{
			auto indexExpr = expr->getIndexExpression()->accept(this);
			return defaultHandler(expr, indexExpr);
		}

		return defaultHandler(expr, {});
	}

	virtual Visitee::ReturnType visit(NotExpression* expr) override
	{
		return _handleUnaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(UnaryMinusExpression* expr) override
	{
		return _handleUnaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(BitwiseNotExpression* expr) override
	{
		return _handleUnaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(AndExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(OrExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(LtExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(GtExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(LeExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(GeExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(EqExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(NeqExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(ContainsExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(MatchesExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(PlusExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(MinusExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(MultiplyExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(DivideExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(ModuloExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(BitwiseXorExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(BitwiseAndExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(BitwiseOrExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(ShiftLeftExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(ShiftRightExpression* expr) override
	{
		return _handleBinaryOperation(expr);
	}

	virtual Visitee::ReturnType visit(ForIntExpression* expr) override
	{
		auto var = expr->getVariable()->accept(this);
		auto iteratedSet = expr->getIteratedSet()->accept(this);
		auto body = expr->getBody()->accept(this);
		return defaultHandler(expr, var, iteratedSet, body);
	}

	virtual Visitee::ReturnType visit(ForStringExpression* expr) override
	{
		auto var = expr->getVariable()->accept(this);
		auto iteratedSet = expr->getIteratedSet()->accept(this);
		auto body = expr->getBody()->accept(this);
		return defaultHandler(expr, var, iteratedSet, body);
	}

	virtual Visitee::ReturnType visit(OfExpression* expr) override
	{
		auto var = expr->getVariable()->accept(this);
		auto iteratedSet = expr->getIteratedSet()->accept(this);
		return defaultHandler(expr, var, iteratedSet, {});
	}

	virtual Visitee::ReturnType visit(SetExpression* expr) override
	{
		std::vector<Visitee::ReturnType> newElements;
		for (auto& element : expr->getElements())
			newElements.push_back(element->accept(this));

		return defaultHandler(expr, newElements);
	}

	virtual Visitee::ReturnType visit(RangeExpression* expr) override
	{
		auto low = expr->getLow()->accept(this);
		auto high = expr->getHigh()->accept(this);
		return defaultHandler(expr, low, high);
	}

	virtual Visitee::ReturnType visit(IdExpression*) override { return {}; }

	virtual Visitee::ReturnType visit(StructAccessExpression* expr) override
	{
		auto structure = expr->getStructure()->accept(this);
		return defaultHandler(expr, structure);
	}

	virtual Visitee::ReturnType visit(ArrayAccessExpression* expr) override
	{
		auto array = expr->getArray()->accept(this);
		auto accessor = expr->getAccessor()->accept(this);
		return defaultHandler(expr, array, accessor);
	}

	virtual Visitee::ReturnType visit(FunctionCallExpression* expr) override
	{
		auto function = expr->getFunction()->accept(this);

		std::vector<Visitee::ReturnType> arguments;
		for (auto& arg : expr->getArguments())
		{
			arguments.push_back(arg->accept(this));
		}

		return defaultHandler(expr, function, arguments);
	}

	virtual Visitee::ReturnType visit(BoolLiteralExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(StringLiteralExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(IntLiteralExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(DoubleLiteralExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(FilesizeExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(EntrypointExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(AllExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(AnyExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(ThemExpression*) override { return {}; }

	virtual Visitee::ReturnType visit(ParenthesesExpression* expr) override
	{
		auto enclosedExpr = expr->getEnclosedExpression()->accept(this);
		return defaultHandler(expr, enclosedExpr);
	}

	virtual Visitee::ReturnType visit(IntFunctionExpression* expr) override
	{
		auto argument = expr->getArgument()->accept(this);
		return defaultHandler(expr, argument);
	}

	virtual Visitee::ReturnType visit(RegexpExpression*) override { return {}; }
	/// @}

	/// @name Default handlers
	/// @{
	Visitee::ReturnType defaultHandler(StringAtExpression* expr, const Visitee::ReturnType& atExpr)
	{
		if (atExpr)
			expr->setAtExpression(atExpr.value());

		if (!expr->getAtExpression())
			return { nullptr };

		return {};
	}

	Visitee::ReturnType defaultHandler(StringInRangeExpression* expr, const Visitee::ReturnType& rangeExpr)
	{
		if (rangeExpr)
			expr->setRangeExpression(rangeExpr.value());

		if (!expr->getRangeExpression())
			return { nullptr };

		return {};
	}

	template <typename T>
	std::enable_if_t<isAnyOf<T, StringOffsetExpression, StringLengthExpression>::value, Visitee::ReturnType>
		defaultHandler(T* expr, const Visitee::ReturnType& indexExpr)
	{
		if (indexExpr)
			expr->setIndexExpression(indexExpr.value());

		if (!expr->getIndexExpression())
			return { nullptr };

		return {};
	}

	template <typename T>
	std::enable_if_t<std::is_base_of<UnaryOpExpression, T>::value, Visitee::ReturnType>
		defaultHandler(T* expr, const Visitee::ReturnType& operand)
	{
		if (operand)
			expr->setOperand(operand.value());

		if (!expr->getOperand())
			return { nullptr };

		return {};
	}

	template <typename T>
	std::enable_if_t<std::is_base_of<BinaryOpExpression, T>::value, Visitee::ReturnType>
		defaultHandler(T* expr, const Visitee::ReturnType& left, const Visitee::ReturnType& right)
	{
		if (left)
			expr->setLeftOperand(left.value());

		if (right)
			expr->setRightOperand(right.value());

		if (!expr->getLeftOperand() && !expr->getRightOperand())
			return { nullptr };
		else if (!expr->getLeftOperand() && expr->getRightOperand())
			return expr->getRightOperand();
		else if (expr->getLeftOperand() && !expr->getRightOperand())
			return expr->getLeftOperand();

		return {};
	}

	template <typename T>
	std::enable_if_t<std::is_base_of<ForExpression, T>::value, Visitee::ReturnType>
		defaultHandler(T* expr, const Visitee::ReturnType& var, const Visitee::ReturnType& iteratedSet, const Visitee::ReturnType& body)
	{
		if (var)
			expr->setVariable(var.value());

		if (iteratedSet)
			expr->setIteratedSet(iteratedSet.value());

		if (body)
			expr->setBody(body.value());

		if (!expr->getVariable() || !expr->getIteratedSet() || (body && !expr->getBody()))
			return { nullptr };

		return {};
	}

	Visitee::ReturnType defaultHandler(SetExpression* expr, const std::vector<Visitee::ReturnType>& elements)
	{
		if (elements.empty())
			return { nullptr };

		if (!std::all_of(elements.begin(), elements.end(),
				[](const auto& element) {
					return !element.has_value();
				}))
		{
			return {};
		}

		std::vector<ASTNode::Ptr> newElements;
		for (std::size_t i = 0, end = elements.size(); i < end; ++i)
		{
			newElements.push_back(elements[i].value_or(expr->getElements()[i]));
		}

		expr->setElements(newElements);
		return {};
	}

	Visitee::ReturnType defaultHandler(RangeExpression* expr, const Visitee::ReturnType& low, const Visitee::ReturnType& high)
	{
		if (low)
			expr->setLow(low.value());

		if (high)
			expr->setHigh(high.value());

		if (!expr->getLow() || !expr->getHigh())
			return { nullptr };

		return {};
	}

	Visitee::ReturnType defaultHandler(StructAccessExpression* expr, const Visitee::ReturnType& structure)
	{
		if (structure)
			expr->setStructure(structure.value());

		if (!expr->getStructure())
			return { nullptr };

		return {};
	}

	Visitee::ReturnType defaultHandler(ArrayAccessExpression* expr, const Visitee::ReturnType& array, const Visitee::ReturnType& accessor)
	{
		if (array)
			expr->setArray(array.value());

		if (accessor)
			expr->setAccessor(accessor.value());

		if (!expr->getArray() || !expr->getAccessor())
			return { nullptr };

		return {};
	}

	Visitee::ReturnType defaultHandler(FunctionCallExpression* expr, const Visitee::ReturnType& function, const std::vector<Visitee::ReturnType>& arguments)
	{
		if (function)
			expr->setFunction(function.value());

		if (!std::all_of(arguments.begin(), arguments.end(),
				[](const auto& arg) {
					return !arg.has_value();
				}))
		{
			return {};
		}

		std::vector<ASTNode::Ptr> newArguments;
		for (std::size_t i = 0, end = arguments.size(); i < end; ++i)
		{
			newArguments.push_back(arguments[i].value_or(expr->getArguments()[i]));
		}

		expr->setArguments(newArguments);
		return {};
	}

	Visitee::ReturnType defaultHandler(ParenthesesExpression* expr, const Visitee::ReturnType& enclosedExpr)
	{
		if (enclosedExpr)
			expr->setEnclosedExpression(enclosedExpr.value());

		if (!expr->getEnclosedExpression())
			return { nullptr };

		return {};
	}

	Visitee::ReturnType defaultHandler(IntFunctionExpression* expr, const Visitee::ReturnType& argument)
	{
		if (argument)
			expr->setArgument(argument.value());

		if (!expr->getArgument())
			return { nullptr };
	
		return {};
	}
	/// @}

protected:
	ModifyingVisitor() = default;

private:
	template <typename T>
	Visitee::ReturnType _handleUnaryOperation(T* expr)
	{
		auto operand = expr->getOperand()->accept(this);
		return defaultHandler(expr, operand);
	}

	template <typename T>
	Visitee::ReturnType _handleBinaryOperation(T* expr)
	{
		auto leftOperand = expr->getLeftOperand()->accept(this);
		auto rightOperand = expr->getRightOperand()->accept(this);
		return defaultHandler(expr, leftOperand, rightOperand);
	}
};

}
