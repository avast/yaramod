#pragma once

#include <pybind11/pybind11.h>

#include <yaramod/utils/deep_visitor.h>
#include <yaramod/utils/passive_visitor.h>
#include <yaramod/utils/visitor.h>

#define PURE_VISIT(type) \
	virtual void visit(yaramod::type* expr) override { \
		PYBIND11_OVERLOAD_PURE_NAME( \
				void, \
				yaramod::Visitor, \
				"visit_"#type, \
				visit, \
				expr \
			); \
	}

class PyVisitor : public yaramod::Visitor
{
public:
	using yaramod::Visitor::Visitor;

	PURE_VISIT(StringExpression)
	PURE_VISIT(StringWildcardExpression)
	PURE_VISIT(StringAtExpression)
	PURE_VISIT(StringInRangeExpression)
	PURE_VISIT(StringCountExpression)
	PURE_VISIT(StringOffsetExpression)
	PURE_VISIT(StringLengthExpression)
	PURE_VISIT(NotExpression)
	PURE_VISIT(UnaryMinusExpression)
	PURE_VISIT(BitwiseNotExpression)
	PURE_VISIT(AndExpression)
	PURE_VISIT(OrExpression)
	PURE_VISIT(LtExpression)
	PURE_VISIT(GtExpression)
	PURE_VISIT(LeExpression)
	PURE_VISIT(GeExpression)
	PURE_VISIT(EqExpression)
	PURE_VISIT(NeqExpression)
	PURE_VISIT(ContainsExpression)
	PURE_VISIT(MatchesExpression)
	PURE_VISIT(PlusExpression)
	PURE_VISIT(MinusExpression)
	PURE_VISIT(MultiplyExpression)
	PURE_VISIT(DivideExpression)
	PURE_VISIT(ModuloExpression)
	PURE_VISIT(BitwiseXorExpression)
	PURE_VISIT(BitwiseAndExpression)
	PURE_VISIT(BitwiseOrExpression)
	PURE_VISIT(ShiftLeftExpression)
	PURE_VISIT(ShiftRightExpression)
	PURE_VISIT(ForIntExpression)
	PURE_VISIT(ForStringExpression)
	PURE_VISIT(OfExpression)
	PURE_VISIT(SetExpression)
	PURE_VISIT(RangeExpression)
	PURE_VISIT(IdExpression)
	PURE_VISIT(StructAccessExpression)
	PURE_VISIT(ArrayAccessExpression)
	PURE_VISIT(FunctionCallExpression)
	PURE_VISIT(BoolLiteralExpression)
	PURE_VISIT(StringLiteralExpression)
	PURE_VISIT(IntLiteralExpression)
	PURE_VISIT(DoubleLiteralExpression)
	PURE_VISIT(FilesizeExpression)
	PURE_VISIT(EntrypointExpression)
	PURE_VISIT(AllExpression)
	PURE_VISIT(AnyExpression)
	PURE_VISIT(ThemExpression)
	PURE_VISIT(ParenthesesExpression)
	PURE_VISIT(IntFunctionExpression)
	PURE_VISIT(RegexpExpression)
};

#define VISIT(parent, type) \
	virtual void visit(yaramod::type* expr) override { \
		PYBIND11_OVERLOAD_NAME( \
				void, \
				yaramod::parent, \
				"visit_"#type, \
				visit, \
				expr \
			); \
	}

class PyDeepVisitor : public yaramod::DeepVisitor
{
public:
	using yaramod::DeepVisitor::DeepVisitor;

	VISIT(DeepVisitor, StringExpression)
	VISIT(DeepVisitor, StringWildcardExpression)
	VISIT(DeepVisitor, StringAtExpression)
	VISIT(DeepVisitor, StringInRangeExpression)
	VISIT(DeepVisitor, StringCountExpression)
	VISIT(DeepVisitor, StringOffsetExpression)
	VISIT(DeepVisitor, StringLengthExpression)
	VISIT(DeepVisitor, NotExpression)
	VISIT(DeepVisitor, UnaryMinusExpression)
	VISIT(DeepVisitor, BitwiseNotExpression)
	VISIT(DeepVisitor, AndExpression)
	VISIT(DeepVisitor, OrExpression)
	VISIT(DeepVisitor, LtExpression)
	VISIT(DeepVisitor, GtExpression)
	VISIT(DeepVisitor, LeExpression)
	VISIT(DeepVisitor, GeExpression)
	VISIT(DeepVisitor, EqExpression)
	VISIT(DeepVisitor, NeqExpression)
	VISIT(DeepVisitor, ContainsExpression)
	VISIT(DeepVisitor, MatchesExpression)
	VISIT(DeepVisitor, PlusExpression)
	VISIT(DeepVisitor, MinusExpression)
	VISIT(DeepVisitor, MultiplyExpression)
	VISIT(DeepVisitor, DivideExpression)
	VISIT(DeepVisitor, ModuloExpression)
	VISIT(DeepVisitor, BitwiseXorExpression)
	VISIT(DeepVisitor, BitwiseAndExpression)
	VISIT(DeepVisitor, BitwiseOrExpression)
	VISIT(DeepVisitor, ShiftLeftExpression)
	VISIT(DeepVisitor, ShiftRightExpression)
	VISIT(DeepVisitor, ForIntExpression)
	VISIT(DeepVisitor, ForStringExpression)
	VISIT(DeepVisitor, OfExpression)
	VISIT(DeepVisitor, SetExpression)
	VISIT(DeepVisitor, RangeExpression)
	VISIT(DeepVisitor, IdExpression)
	VISIT(DeepVisitor, StructAccessExpression)
	VISIT(DeepVisitor, ArrayAccessExpression)
	VISIT(DeepVisitor, FunctionCallExpression)
	VISIT(DeepVisitor, BoolLiteralExpression)
	VISIT(DeepVisitor, StringLiteralExpression)
	VISIT(DeepVisitor, IntLiteralExpression)
	VISIT(DeepVisitor, DoubleLiteralExpression)
	VISIT(DeepVisitor, FilesizeExpression)
	VISIT(DeepVisitor, EntrypointExpression)
	VISIT(DeepVisitor, AllExpression)
	VISIT(DeepVisitor, AnyExpression)
	VISIT(DeepVisitor, ThemExpression)
	VISIT(DeepVisitor, ParenthesesExpression)
	VISIT(DeepVisitor, IntFunctionExpression)
	VISIT(DeepVisitor, RegexpExpression)
};

class PyPassiveVisitor : public yaramod::PassiveVisitor
{
public:
	using yaramod::PassiveVisitor::PassiveVisitor;

	VISIT(PassiveVisitor, StringExpression)
	VISIT(PassiveVisitor, StringWildcardExpression)
	VISIT(PassiveVisitor, StringAtExpression)
	VISIT(PassiveVisitor, StringInRangeExpression)
	VISIT(PassiveVisitor, StringCountExpression)
	VISIT(PassiveVisitor, StringOffsetExpression)
	VISIT(PassiveVisitor, StringLengthExpression)
	VISIT(PassiveVisitor, NotExpression)
	VISIT(PassiveVisitor, UnaryMinusExpression)
	VISIT(PassiveVisitor, BitwiseNotExpression)
	VISIT(PassiveVisitor, AndExpression)
	VISIT(PassiveVisitor, OrExpression)
	VISIT(PassiveVisitor, LtExpression)
	VISIT(PassiveVisitor, GtExpression)
	VISIT(PassiveVisitor, LeExpression)
	VISIT(PassiveVisitor, GeExpression)
	VISIT(PassiveVisitor, EqExpression)
	VISIT(PassiveVisitor, NeqExpression)
	VISIT(PassiveVisitor, ContainsExpression)
	VISIT(PassiveVisitor, MatchesExpression)
	VISIT(PassiveVisitor, PlusExpression)
	VISIT(PassiveVisitor, MinusExpression)
	VISIT(PassiveVisitor, MultiplyExpression)
	VISIT(PassiveVisitor, DivideExpression)
	VISIT(PassiveVisitor, ModuloExpression)
	VISIT(PassiveVisitor, BitwiseXorExpression)
	VISIT(PassiveVisitor, BitwiseAndExpression)
	VISIT(PassiveVisitor, BitwiseOrExpression)
	VISIT(PassiveVisitor, ShiftLeftExpression)
	VISIT(PassiveVisitor, ShiftRightExpression)
	VISIT(PassiveVisitor, ForIntExpression)
	VISIT(PassiveVisitor, ForStringExpression)
	VISIT(PassiveVisitor, OfExpression)
	VISIT(PassiveVisitor, SetExpression)
	VISIT(PassiveVisitor, RangeExpression)
	VISIT(PassiveVisitor, IdExpression)
	VISIT(PassiveVisitor, StructAccessExpression)
	VISIT(PassiveVisitor, ArrayAccessExpression)
	VISIT(PassiveVisitor, FunctionCallExpression)
	VISIT(PassiveVisitor, BoolLiteralExpression)
	VISIT(PassiveVisitor, StringLiteralExpression)
	VISIT(PassiveVisitor, IntLiteralExpression)
	VISIT(PassiveVisitor, DoubleLiteralExpression)
	VISIT(PassiveVisitor, FilesizeExpression)
	VISIT(PassiveVisitor, EntrypointExpression)
	VISIT(PassiveVisitor, AllExpression)
	VISIT(PassiveVisitor, AnyExpression)
	VISIT(PassiveVisitor, ThemExpression)
	VISIT(PassiveVisitor, ParenthesesExpression)
	VISIT(PassiveVisitor, IntFunctionExpression)
	VISIT(PassiveVisitor, RegexpExpression)
};

void addVisitorClasses(pybind11::module& module);
