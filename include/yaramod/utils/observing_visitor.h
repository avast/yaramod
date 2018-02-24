/**
 * @file src/utils/observing_visitor.h
 * @brief Declaration of ObservingVisitor class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/types/expressions.h"
#include "yaramod/utils/visitor.h"

namespace yaramod {

/**
 * Abstract class representing observing visitor of condition expression in YARA files.
 * Its main purpose is just to traverse AST and collect information from it. Even though
 * each visit() method has return value same as with ModifyingVisitor it should be only
 * used to pass around information when collecting data, not directly for modification
 * of AST. If you implement all the logic of modification youself, you can do that but there
 * is no reason to do it on your own and not use ModifyingVisitor.
 */
class ObservingVisitor : public Visitor
{
public:
	void observe(const ASTNode::Ptr& expr)
	{
		expr->accept(this);
	}

	/// @name Visit methods
	/// @{
	virtual Visitee::ReturnType visit(StringExpression*) override { return {}; }
	virtual Visitee::ReturnType visit(StringWildcardExpression*) override { return {}; }

	virtual Visitee::ReturnType visit(StringAtExpression* expr) override
	{
		expr->getAtExpression()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(StringInRangeExpression* expr) override
	{
		expr->getRangeExpression()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(StringCountExpression*) override { return {}; }

	virtual Visitee::ReturnType visit(StringOffsetExpression* expr) override
	{
		if (auto indexExpression = expr->getIndexExpression())
			indexExpression->accept(this);

		return {};
	}

	virtual Visitee::ReturnType visit(StringLengthExpression* expr) override
	{
		if (auto indexExpression = expr->getIndexExpression())
			indexExpression->accept(this);

		return {};
	}

	virtual Visitee::ReturnType visit(NotExpression* expr) override
	{
		expr->getOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(UnaryMinusExpression* expr) override
	{
		expr->getOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(BitwiseNotExpression* expr) override
	{
		expr->getOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(AndExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(OrExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(LtExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(GtExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(LeExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(GeExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(EqExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(NeqExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(ContainsExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(MatchesExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(PlusExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(MinusExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(MultiplyExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(DivideExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(ModuloExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(BitwiseXorExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(BitwiseAndExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(BitwiseOrExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(ShiftLeftExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(ShiftRightExpression* expr) override
	{
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(ForIntExpression* expr) override
	{
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
		expr->getBody()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(ForStringExpression* expr) override
	{
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
		expr->getBody()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(OfExpression* expr) override
	{
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(SetExpression* expr) override
	{
		for (auto& element : expr->getElements())
			element->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(RangeExpression* expr) override
	{
		expr->getLow()->accept(this);
		expr->getHigh()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(IdExpression*) override { return {}; }

	virtual Visitee::ReturnType visit(StructAccessExpression* expr) override
	{
		expr->getStructure()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(ArrayAccessExpression* expr) override
	{
		expr->getArray()->accept(this);
		expr->getAccessor()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(FunctionCallExpression* expr) override
	{
		expr->getFunction()->accept(this);
		for (auto& arg : expr->getArguments())
			arg->accept(this);
		return {};
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
		expr->getEnclosedExpression()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(IntFunctionExpression* expr) override
	{
		expr->getArgument()->accept(this);
		return {};
	}

	virtual Visitee::ReturnType visit(RegexpExpression*) override { return {}; }
	/// @}



protected:
	ObservingVisitor() = default;
};

}
