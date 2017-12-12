/**
 * @file src/utils/deep_visitor.h
 * @brief Declaration of DeepVisitor class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/types/expressions.h"
#include "yaramod/utils/visitor.h"

namespace yaramod {

/**
 * Abstract class representing deep visitor of condition expression in YARA files.
 * It visits all expressions in AST. This visitor can be used if you want to implement
 * specific @c visit method only for certain types of expressions but still traverse them all.
 */
class DeepVisitor : public Visitor
{
public:
	/// @name Visit methods
	/// @{
	virtual void visit(StringExpression*) override {}
	virtual void visit(StringWildcardExpression*) override {}

	virtual void visit(StringAtExpression* expr) override
	{
		expr->getAtExpression()->accept(this);
	}

	virtual void visit(StringInRangeExpression* expr) override
	{
		expr->getRangeExpression()->accept(this);
	}

	virtual void visit(StringCountExpression*) override {}

	virtual void visit(StringOffsetExpression* expr) override
	{
		if (auto indexExpression = expr->getIndexExpression())
			indexExpression->accept(this);
	}

	virtual void visit(StringLengthExpression* expr) override
	{
		if (auto indexExpression = expr->getIndexExpression())
			indexExpression->accept(this);
	}

	virtual void visit(NotExpression* expr) override
	{
		expr->getOperand()->accept(this);
	}

	virtual void visit(UnaryMinusExpression* expr) override
	{
		expr->getOperand()->accept(this);
	}

	virtual void visit(BitwiseNotExpression* expr) override
	{
		expr->getOperand()->accept(this);
	}

	virtual void visit(AndExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(OrExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(LtExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(GtExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(LeExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(GeExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(EqExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(NeqExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(ContainsExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(MatchesExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(PlusExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(MinusExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(MultiplyExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(DivideExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(ModuloExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(BitwiseXorExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(BitwiseAndExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(BitwiseOrExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(ShiftLeftExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(ShiftRightExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
	}

	virtual void visit(ForIntExpression* expr) override
	{
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
		expr->getBody()->accept(this);
	}

	virtual void visit(ForStringExpression* expr) override
	{
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
		expr->getBody()->accept(this);
	}

	virtual void visit(OfExpression* expr) override
	{
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
	}

	virtual void visit(SetExpression* expr) override
	{
		for (auto& element : expr->getElements())
			element->accept(this);
	}

	virtual void visit(RangeExpression* expr) override
	{
		expr->getLow()->accept(this);
		expr->getHigh()->accept(this);
	}

	virtual void visit(IdExpression*) override {}

	virtual void visit(StructAccessExpression* expr) override
	{
		expr->getStructure()->accept(this);
	}

	virtual void visit(ArrayAccessExpression* expr) override
	{
		expr->getArray()->accept(this);
		expr->getAccessor()->accept(this);
	}

	virtual void visit(FunctionCallExpression* expr) override
	{
		expr->getFunction()->accept(this);
		for (auto& arg : expr->getArguments())
			arg->accept(this);
	}

	virtual void visit(BoolLiteralExpression*) override {}
	virtual void visit(StringLiteralExpression*) override {}
	virtual void visit(IntLiteralExpression*) override {}
	virtual void visit(DoubleLiteralExpression*) override {}
	virtual void visit(FilesizeExpression*) override {}
	virtual void visit(EntrypointExpression*) override {}
	virtual void visit(AllExpression*) override {}
	virtual void visit(AnyExpression*) override {}
	virtual void visit(ThemExpression*) override {}

	virtual void visit(ParenthesesExpression* expr) override
	{
		expr->getEnclosedExpression()->accept(this);
	}

	virtual void visit(IntFunctionExpression* expr) override
	{
		expr->getArgument()->accept(this);
	}

	virtual void visit(RegexpExpression*) override {}
	/// @}

protected:
	DeepVisitor() = default;
};

}
