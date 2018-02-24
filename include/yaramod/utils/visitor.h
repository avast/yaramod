/**
 * @file src/utils/visitor.h
 * @brief Declaration of Visitor class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/utils/visitee.h"

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
	virtual Visitee::ReturnType visit(StringExpression* expr) = 0;
	virtual Visitee::ReturnType visit(StringWildcardExpression* expr) = 0;
	virtual Visitee::ReturnType visit(StringAtExpression* expr) = 0;
	virtual Visitee::ReturnType visit(StringInRangeExpression* expr) = 0;
	virtual Visitee::ReturnType visit(StringCountExpression* expr) = 0;
	virtual Visitee::ReturnType visit(StringOffsetExpression* expr) = 0;
	virtual Visitee::ReturnType visit(StringLengthExpression* expr) = 0;
	virtual Visitee::ReturnType visit(NotExpression* expr) = 0;
	virtual Visitee::ReturnType visit(UnaryMinusExpression* expr) = 0;
	virtual Visitee::ReturnType visit(BitwiseNotExpression* expr) = 0;
	virtual Visitee::ReturnType visit(AndExpression* expr) = 0;
	virtual Visitee::ReturnType visit(OrExpression* expr) = 0;
	virtual Visitee::ReturnType visit(LtExpression* expr) = 0;
	virtual Visitee::ReturnType visit(GtExpression* expr) = 0;
	virtual Visitee::ReturnType visit(LeExpression* expr) = 0;
	virtual Visitee::ReturnType visit(GeExpression* expr) = 0;
	virtual Visitee::ReturnType visit(EqExpression* expr) = 0;
	virtual Visitee::ReturnType visit(NeqExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ContainsExpression* expr) = 0;
	virtual Visitee::ReturnType visit(MatchesExpression* expr) = 0;
	virtual Visitee::ReturnType visit(PlusExpression* expr) = 0;
	virtual Visitee::ReturnType visit(MinusExpression* expr) = 0;
	virtual Visitee::ReturnType visit(MultiplyExpression* expr) = 0;
	virtual Visitee::ReturnType visit(DivideExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ModuloExpression* expr) = 0;
	virtual Visitee::ReturnType visit(BitwiseXorExpression* expr) = 0;
	virtual Visitee::ReturnType visit(BitwiseAndExpression* expr) = 0;
	virtual Visitee::ReturnType visit(BitwiseOrExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ShiftLeftExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ShiftRightExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ForIntExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ForStringExpression* expr) = 0;
	virtual Visitee::ReturnType visit(OfExpression* expr) = 0;
	virtual Visitee::ReturnType visit(SetExpression* expr) = 0;
	virtual Visitee::ReturnType visit(RangeExpression* expr) = 0;
	virtual Visitee::ReturnType visit(IdExpression* expr) = 0;
	virtual Visitee::ReturnType visit(StructAccessExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ArrayAccessExpression* expr) = 0;
	virtual Visitee::ReturnType visit(FunctionCallExpression* expr) = 0;
	virtual Visitee::ReturnType visit(BoolLiteralExpression* expr) = 0;
	virtual Visitee::ReturnType visit(StringLiteralExpression* expr) = 0;
	virtual Visitee::ReturnType visit(IntLiteralExpression* expr) = 0;
	virtual Visitee::ReturnType visit(DoubleLiteralExpression* expr) = 0;
	virtual Visitee::ReturnType visit(FilesizeExpression* expr) = 0;
	virtual Visitee::ReturnType visit(EntrypointExpression* expr) = 0;
	virtual Visitee::ReturnType visit(AllExpression* expr) = 0;
	virtual Visitee::ReturnType visit(AnyExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ThemExpression* expr) = 0;
	virtual Visitee::ReturnType visit(ParenthesesExpression* expr) = 0;
	virtual Visitee::ReturnType visit(IntFunctionExpression* expr) = 0;
	virtual Visitee::ReturnType visit(RegexpExpression* expr) = 0;
	/// @}
};

}
