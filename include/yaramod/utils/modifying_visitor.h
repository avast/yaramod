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
 * @c Visitee::ReturnType what is just an alis for `variant<shared_ptr<ASTNode>, Visitee::Action>`.
 * There are 3 possible values you can return in order to control the behavior of the visitor:
 *
 * 1. nullptr - Returning unset variant means keeping the node as it is and not modifying it all.
 * 2. non nullptr - Returning valid instance of ASTNode means replace this AST node with the one I returned you.
 * 3. Visitee::Action::Delete - Delete this AST node.
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
		auto result = expr->accept(this);

		if (auto newExpr = mpark::get_if<ASTNode::Ptr>(&result))
		{
			if (*newExpr)
				expr->setExpression((*newExpr)->getExpression());
		}
		else
			expr->setExpression(makeASTNode<BoolLiteralExpression>(true)->getExpression());
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
	Visitee::ReturnType defaultHandler(StringAtExpression* expr, const Visitee::ReturnType& atExprRet)
	{
		if (auto atExpr = mpark::get_if<ASTNode::Ptr>(&atExprRet))
		{
			if (*atExpr)
				expr->setAtExpression(*atExpr);
		}
		else
			expr->setAtExpression(nullptr);

		if (!expr->getAtExpression())
			return Visitee::Action::Delete;

		return {};
	}

	Visitee::ReturnType defaultHandler(StringInRangeExpression* expr, const Visitee::ReturnType& rangeExprRet)
	{
		if (auto rangeExpr = mpark::get_if<ASTNode::Ptr>(&rangeExprRet))
		{
			if (*rangeExpr)
				expr->setRangeExpression(*rangeExpr);
		}
		else
			expr->setRangeExpression(nullptr);

		if (!expr->getRangeExpression())
			return Visitee::Action::Delete;

		return {};
	}

	template <typename T>
	std::enable_if_t<isAnyOf<T, StringOffsetExpression, StringLengthExpression>::value, Visitee::ReturnType>
		defaultHandler(T* expr, const Visitee::ReturnType& indexExprRet)
	{
		if (auto indexExpr = mpark::get_if<ASTNode::Ptr>(&indexExprRet))
		{
			if (*indexExpr)
				expr->setIndexExpression(*indexExpr);
		}
		else
			expr->setIndexExpression(nullptr);

		if (!expr->getIndexExpression())
			return Visitee::Action::Delete;

		return {};
	}

	template <typename T>
	std::enable_if_t<std::is_base_of<UnaryOpExpression, T>::value, Visitee::ReturnType>
		defaultHandler(T* expr, const Visitee::ReturnType& operandRet)
	{
		if (auto operand = mpark::get_if<ASTNode::Ptr>(&operandRet))
		{
			if (*operand)
				expr->setOperand(*operand);
		}
		else
			return Visitee::Action::Delete;

		return {};
	}

	template <typename T>
	std::enable_if_t<std::is_base_of<BinaryOpExpression, T>::value, Visitee::ReturnType>
		defaultHandler(T* expr, const Visitee::ReturnType& leftRet, const Visitee::ReturnType& rightRet)
	{
		if (auto left = mpark::get_if<ASTNode::Ptr>(&leftRet))
		{
			if (left)
				expr->setLeftOperand(*left);
		}
		else
			expr->setLeftOperand(nullptr);

		if (auto right = mpark::get_if<ASTNode::Ptr>(&rightRet))
		{
			if (right)
				expr->setRightOperand(*right);
		}
		else
			expr->setRightOperand(nullptr);

		if (!expr->getLeftOperand() && !expr->getRightOperand())
			return Visitee::Action::Delete;
		else if (!expr->getLeftOperand() && expr->getRightOperand())
			return expr->getRightOperand();
		else if (expr->getLeftOperand() && !expr->getRightOperand())
			return expr->getLeftOperand();

		return {};
	}

	template <typename T>
	std::enable_if_t<std::is_base_of<ForExpression, T>::value, Visitee::ReturnType>
		defaultHandler(T* expr, const Visitee::ReturnType& varRet, const Visitee::ReturnType& iteratedSetRet, const Visitee::ReturnType& bodyRet)
	{
		if (auto var = mpark::get_if<ASTNode::Ptr>(&varRet))
		{
			if (*var)
				expr->setVariable(*var);
		}
		else
			expr->setVariable(nullptr);

		if (auto iteratedSet = mpark::get_if<ASTNode::Ptr>(&iteratedSetRet))
		{
			if (*iteratedSet)
				expr->setIteratedSet(*iteratedSet);
		}
		else
			expr->setIteratedSet(nullptr);

		auto oldBody = expr->getBody();
		if (auto body = mpark::get_if<ASTNode::Ptr>(&bodyRet))
		{
			if (*body)
				expr->setBody(*body);
		}
		else
			expr->setBody(nullptr);

		if (!expr->getVariable() || !expr->getIteratedSet() || (oldBody && !expr->getBody()))
			return Visitee::Action::Delete;

		return {};
	}

	Visitee::ReturnType defaultHandler(SetExpression* expr, const std::vector<Visitee::ReturnType>& elementsRet)
	{
		if (elementsRet.empty())
			return Visitee::Action::Delete;

		if (std::all_of(elementsRet.begin(), elementsRet.end(),
				[](const auto& element) {
					auto e = mpark::get_if<ASTNode::Ptr>(&element);
					return e && (*e == nullptr);
				}))
		{
			return {};
		}

		std::vector<ASTNode::Ptr> newElements;
		for (std::size_t i = 0, end = elementsRet.size(); i < end; ++i)
		{
			if (auto element = mpark::get_if<ASTNode::Ptr>(&elementsRet[i]))
			{
				if (*element)
					newElements.push_back(*element);
				else
					newElements.push_back(expr->getElements()[i]);
			}
		}

		expr->setElements(newElements);
		return {};
	}

	Visitee::ReturnType defaultHandler(RangeExpression* expr, const Visitee::ReturnType& lowRet, const Visitee::ReturnType& highRet)
	{
		if (auto low = mpark::get_if<ASTNode::Ptr>(&lowRet))
		{
			if (*low)
				expr->setLow(*low);
		}
		else
			expr->setLow(nullptr);

		if (auto high = mpark::get_if<ASTNode::Ptr>(&highRet))
		{
			if (*high)
				expr->setHigh(*high);
		}
		else
			expr->setHigh(nullptr);

		if (!expr->getLow() || !expr->getHigh())
			return Visitee::Action::Delete;

		return {};
	}

	Visitee::ReturnType defaultHandler(StructAccessExpression* expr, const Visitee::ReturnType& structureRet)
	{
		if (auto structure = mpark::get_if<ASTNode::Ptr>(&structureRet))
		{
			if (*structure)
				expr->setStructure(*structure);
		}
		else
			return Visitee::Action::Delete;

		return {};
	}

	Visitee::ReturnType defaultHandler(ArrayAccessExpression* expr, const Visitee::ReturnType& arrayRet, const Visitee::ReturnType& accessorRet)
	{
		if (auto array = mpark::get_if<ASTNode::Ptr>(&arrayRet))
		{
			if (*array)
				expr->setArray(*array);
		}
		else
			expr->setArray(nullptr);

		if (auto accessor = mpark::get_if<ASTNode::Ptr>(&accessorRet))
		{
			if (*accessor)
				expr->setAccessor(*accessor);
		}
		else
			expr->setAccessor(nullptr);

		if (!expr->getArray() || !expr->getAccessor())
			return Visitee::Action::Delete;

		return {};
	}

	Visitee::ReturnType defaultHandler(FunctionCallExpression* expr, const Visitee::ReturnType& functionRet, const std::vector<Visitee::ReturnType>& argumentsRet)
	{
		if (auto function = mpark::get_if<ASTNode::Ptr>(&functionRet))
		{
			if (*function)
				expr->setFunction(*function);
		}
		else
			expr->setFunction(nullptr);

		if (std::all_of(argumentsRet.begin(), argumentsRet.end(),
				[](const auto& arg) {
					auto a = mpark::get_if<ASTNode::Ptr>(&arg);
					return a && (*a == nullptr);
				}))
		{
			return {};
		}

		std::vector<ASTNode::Ptr> newArguments;
		for (std::size_t i = 0, end = argumentsRet.size(); i < end; ++i)
		{
			if (auto arg = mpark::get_if<ASTNode::Ptr>(&argumentsRet[i]))
			{
				if (*arg)
					newArguments.push_back(*arg);
				else
					newArguments.push_back(expr->getArguments()[i]);
			}
		}

		expr->setArguments(newArguments);
		return {};
	}

	Visitee::ReturnType defaultHandler(ParenthesesExpression* expr, const Visitee::ReturnType& enclosedExprRet)
	{
		if (auto enclosedExpr = mpark::get_if<ASTNode::Ptr>(&enclosedExprRet))
		{
			if (*enclosedExpr)
				expr->setEnclosedExpression(*enclosedExpr);
		}
		else
			expr->setEnclosedExpression(nullptr);

		if (!expr->getEnclosedExpression())
			return Visitee::Action::Delete;

		return {};
	}

	Visitee::ReturnType defaultHandler(IntFunctionExpression* expr, const Visitee::ReturnType& argumentRet)
	{
		if (auto argument = mpark::get_if<ASTNode::Ptr>(&argumentRet))
		{
			if (*argument)
				expr->setArgument(*argument);
		}
		else
			expr->setArgument(nullptr);

		if (!expr->getArgument())
			return Visitee::Action::Delete;
	
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
