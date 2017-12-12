/**
 * @file src/utils/visitor.h
 * @brief Declaration of Visitor class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

namespace yaramod {

class StringExpression;
class StringWildcardExpression;
class StringAtExpression;
class StringInRangeExpression;
class StringCountExpression;
class StringOffsetExpression;
class StringLengthExpression;
class NotExpression;
class UnaryMinusExpression;
class BitwiseNotExpression;
class AndExpression;
class OrExpression;
class LtExpression;
class GtExpression;
class LeExpression;
class GeExpression;
class EqExpression;
class NeqExpression;
class ContainsExpression;
class MatchesExpression;
class PlusExpression;
class MinusExpression;
class MultiplyExpression;
class DivideExpression;
class ModuloExpression;
class BitwiseXorExpression;
class BitwiseAndExpression;
class BitwiseOrExpression;
class ShiftLeftExpression;
class ShiftRightExpression;
class ForIntExpression;
class ForStringExpression;
class OfExpression;
class SetExpression;
class RangeExpression;
class IdExpression;
class StructAccessExpression;
class ArrayAccessExpression;
class FunctionCallExpression;
class BoolLiteralExpression;
class StringLiteralExpression;
class IntLiteralExpression;
class DoubleLiteralExpression;
class FilesizeExpression;
class EntrypointExpression;
class AllExpression;
class AnyExpression;
class ThemExpression;
class ParenthesesExpression;
class IntFunctionExpression;
class RegexpExpression;

/**
 * Abstract class representing visitor design pattern for visiting condition expressions
 * in YARA file. Subclass this class whenever you want to somehow
 * process expression in conditions.
 */
class Visitor
{
public:
	/// @name Visit methods
	/// @{
	virtual void visit(StringExpression* expr) = 0;
	virtual void visit(StringWildcardExpression* expr) = 0;
	virtual void visit(StringAtExpression* expr) = 0;
	virtual void visit(StringInRangeExpression* expr) = 0;
	virtual void visit(StringCountExpression* expr) = 0;
	virtual void visit(StringOffsetExpression* expr) = 0;
	virtual void visit(StringLengthExpression* expr) = 0;
	virtual void visit(NotExpression* expr) = 0;
	virtual void visit(UnaryMinusExpression* expr) = 0;
	virtual void visit(BitwiseNotExpression* expr) = 0;
	virtual void visit(AndExpression* expr) = 0;
	virtual void visit(OrExpression* expr) = 0;
	virtual void visit(LtExpression* expr) = 0;
	virtual void visit(GtExpression* expr) = 0;
	virtual void visit(LeExpression* expr) = 0;
	virtual void visit(GeExpression* expr) = 0;
	virtual void visit(EqExpression* expr) = 0;
	virtual void visit(NeqExpression* expr) = 0;
	virtual void visit(ContainsExpression* expr) = 0;
	virtual void visit(MatchesExpression* expr) = 0;
	virtual void visit(PlusExpression* expr) = 0;
	virtual void visit(MinusExpression* expr) = 0;
	virtual void visit(MultiplyExpression* expr) = 0;
	virtual void visit(DivideExpression* expr) = 0;
	virtual void visit(ModuloExpression* expr) = 0;
	virtual void visit(BitwiseXorExpression* expr) = 0;
	virtual void visit(BitwiseAndExpression* expr) = 0;
	virtual void visit(BitwiseOrExpression* expr) = 0;
	virtual void visit(ShiftLeftExpression* expr) = 0;
	virtual void visit(ShiftRightExpression* expr) = 0;
	virtual void visit(ForIntExpression* expr) = 0;
	virtual void visit(ForStringExpression* expr) = 0;
	virtual void visit(OfExpression* expr) = 0;
	virtual void visit(SetExpression* expr) = 0;
	virtual void visit(RangeExpression* expr) = 0;
	virtual void visit(IdExpression* expr) = 0;
	virtual void visit(StructAccessExpression* expr) = 0;
	virtual void visit(ArrayAccessExpression* expr) = 0;
	virtual void visit(FunctionCallExpression* expr) = 0;
	virtual void visit(BoolLiteralExpression* expr) = 0;
	virtual void visit(StringLiteralExpression* expr) = 0;
	virtual void visit(IntLiteralExpression* expr) = 0;
	virtual void visit(DoubleLiteralExpression* expr) = 0;
	virtual void visit(FilesizeExpression* expr) = 0;
	virtual void visit(EntrypointExpression* expr) = 0;
	virtual void visit(AllExpression* expr) = 0;
	virtual void visit(AnyExpression* expr) = 0;
	virtual void visit(ThemExpression* expr) = 0;
	virtual void visit(ParenthesesExpression* expr) = 0;
	virtual void visit(IntFunctionExpression* expr) = 0;
	virtual void visit(RegexpExpression* expr) = 0;
	/// @}
};

}
