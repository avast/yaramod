/**
 * @file src/utils/passive_visitor.h
 * @brief Declaration of PassiveVisitor class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/utils/visitor.h"

namespace yaramod {

/**
 * Abstract class representing passive visitor of condition expression in YARA files.
 * It does nothing for every kind of expression. This visitor can be used
 * if you want to implement @c visit method only for certain types of expressions
 * and ignore others.
 */
class PassiveVisitor : public Visitor
{
public:
	/// @name Visit methods
	/// @{
	virtual void visit(StringExpression*) override {}
	virtual void visit(StringWildcardExpression*) override {}
	virtual void visit(StringAtExpression*) override {}
	virtual void visit(StringInRangeExpression*) override {}
	virtual void visit(StringCountExpression*) override {}
	virtual void visit(StringOffsetExpression*) override {}
	virtual void visit(StringLengthExpression*) override {}
	virtual void visit(NotExpression*) override {}
	virtual void visit(UnaryMinusExpression*) override {}
	virtual void visit(BitwiseNotExpression*) override {}
	virtual void visit(AndExpression*) override {}
	virtual void visit(OrExpression*) override {}
	virtual void visit(LtExpression*) override {}
	virtual void visit(GtExpression*) override {}
	virtual void visit(LeExpression*) override {}
	virtual void visit(GeExpression*) override {}
	virtual void visit(EqExpression*) override {}
	virtual void visit(NeqExpression*) override {}
	virtual void visit(ContainsExpression*) override {}
	virtual void visit(MatchesExpression*) override {}
	virtual void visit(PlusExpression*) override {}
	virtual void visit(MinusExpression*) override {}
	virtual void visit(MultiplyExpression*) override {}
	virtual void visit(DivideExpression*) override {}
	virtual void visit(ModuloExpression*) override {}
	virtual void visit(BitwiseXorExpression*) override {}
	virtual void visit(BitwiseAndExpression*) override {}
	virtual void visit(BitwiseOrExpression*) override {}
	virtual void visit(ShiftLeftExpression*) override {}
	virtual void visit(ShiftRightExpression*) override {}
	virtual void visit(ForIntExpression*) override {}
	virtual void visit(ForStringExpression*) override {}
	virtual void visit(OfExpression*) override {}
	virtual void visit(SetExpression*) override {}
	virtual void visit(RangeExpression*) override {}
	virtual void visit(IdExpression*) override {}
	virtual void visit(StructAccessExpression*) override {}
	virtual void visit(ArrayAccessExpression*) override {}
	virtual void visit(FunctionCallExpression*) override {}
	virtual void visit(BoolLiteralExpression*) override {}
	virtual void visit(StringLiteralExpression*) override {}
	virtual void visit(IntLiteralExpression*) override {}
	virtual void visit(DoubleLiteralExpression*) override {}
	virtual void visit(FilesizeExpression*) override {}
	virtual void visit(EntrypointExpression*) override {}
	virtual void visit(AllExpression*) override {}
	virtual void visit(AnyExpression*) override {}
	virtual void visit(ThemExpression*) override {}
	virtual void visit(ParenthesesExpression*) override {}
	virtual void visit(IntFunctionExpression*) override {}
	virtual void visit(RegexpExpression*) override {}
	/// @}

protected:
	PassiveVisitor() = default;
};

}
