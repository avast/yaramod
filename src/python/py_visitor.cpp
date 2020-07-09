/**
 * @file src/python/py_visitor.cpp
 * @brief Implementation of yaramod python bindings for visitors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <yaramod/yaramod.h>

#include "yaramod_python.h"
#include "py_visitor.h"

namespace py = pybind11;
using namespace yaramod;

void addVisitorClasses(py::module& module)
{
	py::class_<TokenStreamContext>(module, "TokenStreamContext")
		.def(py::init<Expression*>());

	py::class_<Visitor, PyVisitor>(module, "Visitor")
		.def(py::init<>())
		.def("visit_StringExpression", py::overload_cast<StringExpression*>(&Visitor::visit))
		.def("visit_StringWildcardExpression", py::overload_cast<StringWildcardExpression*>(&Visitor::visit))
		.def("visit_StringAtExpression", py::overload_cast<StringAtExpression*>(&Visitor::visit))
		.def("visit_StringInRangeExpression", py::overload_cast<StringInRangeExpression*>(&Visitor::visit))
		.def("visit_StringCountExpression", py::overload_cast<StringCountExpression*>(&Visitor::visit))
		.def("visit_StringOffsetExpression", py::overload_cast<StringOffsetExpression*>(&Visitor::visit))
		.def("visit_StringLengthExpression", py::overload_cast<StringLengthExpression*>(&Visitor::visit))
		.def("visit_NotExpression", py::overload_cast<NotExpression*>(&Visitor::visit))
		.def("visit_UnaryMinusExpression", py::overload_cast<UnaryMinusExpression*>(&Visitor::visit))
		.def("visit_BitwiseNotExpression", py::overload_cast<BitwiseNotExpression*>(&Visitor::visit))
		.def("visit_AndExpression", py::overload_cast<AndExpression*>(&Visitor::visit))
		.def("visit_OrExpression", py::overload_cast<OrExpression*>(&Visitor::visit))
		.def("visit_LtExpression", py::overload_cast<LtExpression*>(&Visitor::visit))
		.def("visit_GtExpression", py::overload_cast<GtExpression*>(&Visitor::visit))
		.def("visit_LeExpression", py::overload_cast<LeExpression*>(&Visitor::visit))
		.def("visit_GeExpression", py::overload_cast<GeExpression*>(&Visitor::visit))
		.def("visit_EqExpression", py::overload_cast<EqExpression*>(&Visitor::visit))
		.def("visit_NeqExpression", py::overload_cast<NeqExpression*>(&Visitor::visit))
		.def("visit_ContainsExpression", py::overload_cast<ContainsExpression*>(&Visitor::visit))
		.def("visit_MatchesExpression", py::overload_cast<MatchesExpression*>(&Visitor::visit))
		.def("visit_PlusExpression", py::overload_cast<PlusExpression*>(&Visitor::visit))
		.def("visit_MinusExpression", py::overload_cast<MinusExpression*>(&Visitor::visit))
		.def("visit_MultiplyExpression", py::overload_cast<MultiplyExpression*>(&Visitor::visit))
		.def("visit_DivideExpression", py::overload_cast<DivideExpression*>(&Visitor::visit))
		.def("visit_ModuloExpression", py::overload_cast<ModuloExpression*>(&Visitor::visit))
		.def("visit_BitwiseXorExpression", py::overload_cast<BitwiseXorExpression*>(&Visitor::visit))
		.def("visit_BitwiseAndExpression", py::overload_cast<BitwiseAndExpression*>(&Visitor::visit))
		.def("visit_BitwiseOrExpression", py::overload_cast<BitwiseOrExpression*>(&Visitor::visit))
		.def("visit_ShiftLeftExpression", py::overload_cast<ShiftLeftExpression*>(&Visitor::visit))
		.def("visit_ShiftRightExpression", py::overload_cast<ShiftRightExpression*>(&Visitor::visit))
		.def("visit_ForIntExpression", py::overload_cast<ForIntExpression*>(&Visitor::visit))
		.def("visit_ForStringExpression", py::overload_cast<ForStringExpression*>(&Visitor::visit))
		.def("visit_OfExpression", py::overload_cast<OfExpression*>(&Visitor::visit))
		.def("visit_SetExpression", py::overload_cast<SetExpression*>(&Visitor::visit))
		.def("visit_RangeExpression", py::overload_cast<RangeExpression*>(&Visitor::visit))
		.def("visit_IdExpression", py::overload_cast<IdExpression*>(&Visitor::visit))
		.def("visit_StructAccessExpression", py::overload_cast<StructAccessExpression*>(&Visitor::visit))
		.def("visit_ArrayAccessExpression", py::overload_cast<ArrayAccessExpression*>(&Visitor::visit))
		.def("visit_FunctionCallExpression", py::overload_cast<FunctionCallExpression*>(&Visitor::visit))
		.def("visit_BoolLiteralExpression", py::overload_cast<BoolLiteralExpression*>(&Visitor::visit))
		.def("visit_StringLiteralExpression", py::overload_cast<StringLiteralExpression*>(&Visitor::visit))
		.def("visit_IntLiteralExpression", py::overload_cast<IntLiteralExpression*>(&Visitor::visit))
		.def("visit_DoubleLiteralExpression", py::overload_cast<DoubleLiteralExpression*>(&Visitor::visit))
		.def("visit_FilesizeExpression", py::overload_cast<FilesizeExpression*>(&Visitor::visit))
		.def("visit_EntrypointExpression", py::overload_cast<EntrypointExpression*>(&Visitor::visit))
		.def("visit_AllExpression", py::overload_cast<AllExpression*>(&Visitor::visit))
		.def("visit_AnyExpression", py::overload_cast<AnyExpression*>(&Visitor::visit))
		.def("visit_ThemExpression", py::overload_cast<ThemExpression*>(&Visitor::visit))
		.def("visit_ParenthesesExpression", py::overload_cast<ParenthesesExpression*>(&Visitor::visit))
		.def("visit_IntFunctionExpression", py::overload_cast<IntFunctionExpression*>(&Visitor::visit))
		.def("visit_RegexpExpression", py::overload_cast<RegexpExpression*>(&Visitor::visit));

	py::class_<ObservingVisitor, PyObservingVisitor, Visitor>(module, "ObservingVisitor")
		.def(py::init<>())
		.def("observe", &ObservingVisitor::observe)
		.def("visit_StringExpression", py::overload_cast<StringExpression*>(&ObservingVisitor::visit))
		.def("visit_StringWildcardExpression", py::overload_cast<StringWildcardExpression*>(&ObservingVisitor::visit))
		.def("visit_StringAtExpression", py::overload_cast<StringAtExpression*>(&ObservingVisitor::visit))
		.def("visit_StringInRangeExpression", py::overload_cast<StringInRangeExpression*>(&ObservingVisitor::visit))
		.def("visit_StringCountExpression", py::overload_cast<StringCountExpression*>(&ObservingVisitor::visit))
		.def("visit_StringOffsetExpression", py::overload_cast<StringOffsetExpression*>(&ObservingVisitor::visit))
		.def("visit_StringLengthExpression", py::overload_cast<StringLengthExpression*>(&ObservingVisitor::visit))
		.def("visit_NotExpression", py::overload_cast<NotExpression*>(&ObservingVisitor::visit))
		.def("visit_UnaryMinusExpression", py::overload_cast<UnaryMinusExpression*>(&ObservingVisitor::visit))
		.def("visit_BitwiseNotExpression", py::overload_cast<BitwiseNotExpression*>(&ObservingVisitor::visit))
		.def("visit_AndExpression", py::overload_cast<AndExpression*>(&ObservingVisitor::visit))
		.def("visit_OrExpression", py::overload_cast<OrExpression*>(&ObservingVisitor::visit))
		.def("visit_LtExpression", py::overload_cast<LtExpression*>(&ObservingVisitor::visit))
		.def("visit_GtExpression", py::overload_cast<GtExpression*>(&ObservingVisitor::visit))
		.def("visit_LeExpression", py::overload_cast<LeExpression*>(&ObservingVisitor::visit))
		.def("visit_GeExpression", py::overload_cast<GeExpression*>(&ObservingVisitor::visit))
		.def("visit_EqExpression", py::overload_cast<EqExpression*>(&ObservingVisitor::visit))
		.def("visit_NeqExpression", py::overload_cast<NeqExpression*>(&ObservingVisitor::visit))
		.def("visit_ContainsExpression", py::overload_cast<ContainsExpression*>(&ObservingVisitor::visit))
		.def("visit_MatchesExpression", py::overload_cast<MatchesExpression*>(&ObservingVisitor::visit))
		.def("visit_PlusExpression", py::overload_cast<PlusExpression*>(&ObservingVisitor::visit))
		.def("visit_MinusExpression", py::overload_cast<MinusExpression*>(&ObservingVisitor::visit))
		.def("visit_MultiplyExpression", py::overload_cast<MultiplyExpression*>(&ObservingVisitor::visit))
		.def("visit_DivideExpression", py::overload_cast<DivideExpression*>(&ObservingVisitor::visit))
		.def("visit_ModuloExpression", py::overload_cast<ModuloExpression*>(&ObservingVisitor::visit))
		.def("visit_BitwiseXorExpression", py::overload_cast<BitwiseXorExpression*>(&ObservingVisitor::visit))
		.def("visit_BitwiseAndExpression", py::overload_cast<BitwiseAndExpression*>(&ObservingVisitor::visit))
		.def("visit_BitwiseOrExpression", py::overload_cast<BitwiseOrExpression*>(&ObservingVisitor::visit))
		.def("visit_ShiftLeftExpression", py::overload_cast<ShiftLeftExpression*>(&ObservingVisitor::visit))
		.def("visit_ShiftRightExpression", py::overload_cast<ShiftRightExpression*>(&ObservingVisitor::visit))
		.def("visit_ForIntExpression", py::overload_cast<ForIntExpression*>(&ObservingVisitor::visit))
		.def("visit_ForStringExpression", py::overload_cast<ForStringExpression*>(&ObservingVisitor::visit))
		.def("visit_OfExpression", py::overload_cast<OfExpression*>(&ObservingVisitor::visit))
		.def("visit_SetExpression", py::overload_cast<SetExpression*>(&ObservingVisitor::visit))
		.def("visit_RangeExpression", py::overload_cast<RangeExpression*>(&ObservingVisitor::visit))
		.def("visit_IdExpression", py::overload_cast<IdExpression*>(&ObservingVisitor::visit))
		.def("visit_StructAccessExpression", py::overload_cast<StructAccessExpression*>(&ObservingVisitor::visit))
		.def("visit_ArrayAccessExpression", py::overload_cast<ArrayAccessExpression*>(&ObservingVisitor::visit))
		.def("visit_FunctionCallExpression", py::overload_cast<FunctionCallExpression*>(&ObservingVisitor::visit))
		.def("visit_BoolLiteralExpression", py::overload_cast<BoolLiteralExpression*>(&ObservingVisitor::visit))
		.def("visit_StringLiteralExpression", py::overload_cast<StringLiteralExpression*>(&ObservingVisitor::visit))
		.def("visit_IntLiteralExpression", py::overload_cast<IntLiteralExpression*>(&ObservingVisitor::visit))
		.def("visit_DoubleLiteralExpression", py::overload_cast<DoubleLiteralExpression*>(&ObservingVisitor::visit))
		.def("visit_FilesizeExpression", py::overload_cast<FilesizeExpression*>(&ObservingVisitor::visit))
		.def("visit_EntrypointExpression", py::overload_cast<EntrypointExpression*>(&ObservingVisitor::visit))
		.def("visit_AllExpression", py::overload_cast<AllExpression*>(&ObservingVisitor::visit))
		.def("visit_AnyExpression", py::overload_cast<AnyExpression*>(&ObservingVisitor::visit))
		.def("visit_ThemExpression", py::overload_cast<ThemExpression*>(&ObservingVisitor::visit))
		.def("visit_ParenthesesExpression", py::overload_cast<ParenthesesExpression*>(&ObservingVisitor::visit))
		.def("visit_IntFunctionExpression", py::overload_cast<IntFunctionExpression*>(&ObservingVisitor::visit))
		.def("visit_RegexpExpression", py::overload_cast<RegexpExpression*>(&ObservingVisitor::visit));

	py::class_<ModifyingVisitor, PyModifyingVisitor, Visitor>(module, "ModifyingVisitor")
		.def(py::init<>())
		.def("modify", &ModifyingVisitor::modify, py::arg("expr"), py::arg("when_deleted") = static_cast<Expression*>(nullptr))
		.def("cleanUpTokenStreams", &ModifyingVisitor::cleanUpTokenStreams, py::arg("context"), py::arg("new_expression"))
		.def("visit_StringExpression", py::overload_cast<StringExpression*>(&ModifyingVisitor::visit))
		.def("visit_StringWildcardExpression", py::overload_cast<StringWildcardExpression*>(&ModifyingVisitor::visit))
		.def("visit_StringAtExpression", py::overload_cast<StringAtExpression*>(&ModifyingVisitor::visit))
		.def("visit_StringInRangeExpression", py::overload_cast<StringInRangeExpression*>(&ModifyingVisitor::visit))
		.def("visit_StringCountExpression", py::overload_cast<StringCountExpression*>(&ModifyingVisitor::visit))
		.def("visit_StringOffsetExpression", py::overload_cast<StringOffsetExpression*>(&ModifyingVisitor::visit))
		.def("visit_StringLengthExpression", py::overload_cast<StringLengthExpression*>(&ModifyingVisitor::visit))
		.def("visit_NotExpression", py::overload_cast<NotExpression*>(&ModifyingVisitor::visit))
		.def("visit_UnaryMinusExpression", py::overload_cast<UnaryMinusExpression*>(&ModifyingVisitor::visit))
		.def("visit_BitwiseNotExpression", py::overload_cast<BitwiseNotExpression*>(&ModifyingVisitor::visit))
		.def("visit_AndExpression", py::overload_cast<AndExpression*>(&ModifyingVisitor::visit))
		.def("visit_OrExpression", py::overload_cast<OrExpression*>(&ModifyingVisitor::visit))
		.def("visit_LtExpression", py::overload_cast<LtExpression*>(&ModifyingVisitor::visit))
		.def("visit_GtExpression", py::overload_cast<GtExpression*>(&ModifyingVisitor::visit))
		.def("visit_LeExpression", py::overload_cast<LeExpression*>(&ModifyingVisitor::visit))
		.def("visit_GeExpression", py::overload_cast<GeExpression*>(&ModifyingVisitor::visit))
		.def("visit_EqExpression", py::overload_cast<EqExpression*>(&ModifyingVisitor::visit))
		.def("visit_NeqExpression", py::overload_cast<NeqExpression*>(&ModifyingVisitor::visit))
		.def("visit_ContainsExpression", py::overload_cast<ContainsExpression*>(&ModifyingVisitor::visit))
		.def("visit_MatchesExpression", py::overload_cast<MatchesExpression*>(&ModifyingVisitor::visit))
		.def("visit_PlusExpression", py::overload_cast<PlusExpression*>(&ModifyingVisitor::visit))
		.def("visit_MinusExpression", py::overload_cast<MinusExpression*>(&ModifyingVisitor::visit))
		.def("visit_MultiplyExpression", py::overload_cast<MultiplyExpression*>(&ModifyingVisitor::visit))
		.def("visit_DivideExpression", py::overload_cast<DivideExpression*>(&ModifyingVisitor::visit))
		.def("visit_ModuloExpression", py::overload_cast<ModuloExpression*>(&ModifyingVisitor::visit))
		.def("visit_BitwiseXorExpression", py::overload_cast<BitwiseXorExpression*>(&ModifyingVisitor::visit))
		.def("visit_BitwiseAndExpression", py::overload_cast<BitwiseAndExpression*>(&ModifyingVisitor::visit))
		.def("visit_BitwiseOrExpression", py::overload_cast<BitwiseOrExpression*>(&ModifyingVisitor::visit))
		.def("visit_ShiftLeftExpression", py::overload_cast<ShiftLeftExpression*>(&ModifyingVisitor::visit))
		.def("visit_ShiftRightExpression", py::overload_cast<ShiftRightExpression*>(&ModifyingVisitor::visit))
		.def("visit_ForIntExpression", py::overload_cast<ForIntExpression*>(&ModifyingVisitor::visit))
		.def("visit_ForStringExpression", py::overload_cast<ForStringExpression*>(&ModifyingVisitor::visit))
		.def("visit_OfExpression", py::overload_cast<OfExpression*>(&ModifyingVisitor::visit))
		.def("visit_SetExpression", py::overload_cast<SetExpression*>(&ModifyingVisitor::visit))
		.def("visit_RangeExpression", py::overload_cast<RangeExpression*>(&ModifyingVisitor::visit))
		.def("visit_IdExpression", py::overload_cast<IdExpression*>(&ModifyingVisitor::visit))
		.def("visit_StructAccessExpression", py::overload_cast<StructAccessExpression*>(&ModifyingVisitor::visit))
		.def("visit_ArrayAccessExpression", py::overload_cast<ArrayAccessExpression*>(&ModifyingVisitor::visit))
		.def("visit_FunctionCallExpression", py::overload_cast<FunctionCallExpression*>(&ModifyingVisitor::visit))
		.def("visit_BoolLiteralExpression", py::overload_cast<BoolLiteralExpression*>(&ModifyingVisitor::visit))
		.def("visit_StringLiteralExpression", py::overload_cast<StringLiteralExpression*>(&ModifyingVisitor::visit))
		.def("visit_IntLiteralExpression", py::overload_cast<IntLiteralExpression*>(&ModifyingVisitor::visit))
		.def("visit_DoubleLiteralExpression", py::overload_cast<DoubleLiteralExpression*>(&ModifyingVisitor::visit))
		.def("visit_FilesizeExpression", py::overload_cast<FilesizeExpression*>(&ModifyingVisitor::visit))
		.def("visit_EntrypointExpression", py::overload_cast<EntrypointExpression*>(&ModifyingVisitor::visit))
		.def("visit_AllExpression", py::overload_cast<AllExpression*>(&ModifyingVisitor::visit))
		.def("visit_AnyExpression", py::overload_cast<AnyExpression*>(&ModifyingVisitor::visit))
		.def("visit_ThemExpression", py::overload_cast<ThemExpression*>(&ModifyingVisitor::visit))
		.def("visit_ParenthesesExpression", py::overload_cast<ParenthesesExpression*>(&ModifyingVisitor::visit))
		.def("visit_IntFunctionExpression", py::overload_cast<IntFunctionExpression*>(&ModifyingVisitor::visit))
		.def("visit_RegexpExpression", py::overload_cast<RegexpExpression*>(&ModifyingVisitor::visit))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, StringAtExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, StringInRangeExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, StringOffsetExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, StringLengthExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, NotExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, UnaryMinusExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, BitwiseNotExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, AndExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, OrExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, LtExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, GtExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, LeExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, GeExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, EqExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, NeqExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, ContainsExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, MatchesExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, PlusExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, MinusExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, MultiplyExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, DivideExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, ModuloExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, BitwiseXorExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, BitwiseAndExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, BitwiseOrExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, ShiftLeftExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, ShiftRightExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, ForIntExpression*, const VisitResult&, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, ForStringExpression*, const VisitResult&, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, OfExpression*, const VisitResult&, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, SetExpression*, const std::vector<VisitResult>&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, RangeExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, StructAccessExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, ArrayAccessExpression*, const VisitResult&, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, FunctionCallExpression*, const VisitResult&, const std::vector<VisitResult>&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, ParenthesesExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler))
		.def("default_handler", static_cast<VisitResult(ModifyingVisitor::*)(const TokenStreamContext&, IntFunctionExpression*, const VisitResult&)>(&ModifyingVisitor::defaultHandler));
}

void addRegexpVisitorClasses(py::module& module)
{
	py::class_<RegexpVisitor, PyRegexpVisitor>(module, "RegexpVisitor")
		.def(py::init<>())
		.def("visit_RegexpClass", py::overload_cast<RegexpClass*>(&RegexpVisitor::visit))
		.def("visit_RegexpText", py::overload_cast<RegexpText*>(&RegexpVisitor::visit))
		.def("visit_RegexpAnyChar", py::overload_cast<RegexpAnyChar*>(&RegexpVisitor::visit))
		.def("visit_RegexpWordChar", py::overload_cast<RegexpWordChar*>(&RegexpVisitor::visit))
		.def("visit_RegexpNonWordChar", py::overload_cast<RegexpNonWordChar*>(&RegexpVisitor::visit))
		.def("visit_RegexpSpace", py::overload_cast<RegexpSpace*>(&RegexpVisitor::visit))
		.def("visit_RegexpNonSpace", py::overload_cast<RegexpNonSpace*>(&RegexpVisitor::visit))
		.def("visit_RegexpDigit", py::overload_cast<RegexpDigit*>(&RegexpVisitor::visit))
		.def("visit_RegexpNonDigit", py::overload_cast<RegexpNonDigit*>(&RegexpVisitor::visit))
		.def("visit_RegexpWordBoundary", py::overload_cast<RegexpWordBoundary*>(&RegexpVisitor::visit))
		.def("visit_RegexpNonWordBoundary", py::overload_cast<RegexpNonWordBoundary*>(&RegexpVisitor::visit))
		.def("visit_RegexpStartOfLine", py::overload_cast<RegexpStartOfLine*>(&RegexpVisitor::visit))
		.def("visit_RegexpEndOfLine", py::overload_cast<RegexpEndOfLine*>(&RegexpVisitor::visit))
		.def("visit_RegexpIteration", py::overload_cast<RegexpIteration*>(&RegexpVisitor::visit))
		.def("visit_RegexpPositiveIteration", py::overload_cast<RegexpPositiveIteration*>(&RegexpVisitor::visit))
		.def("visit_RegexpOptional", py::overload_cast<RegexpOptional*>(&RegexpVisitor::visit))
		.def("visit_RegexpRange", py::overload_cast<RegexpRange*>(&RegexpVisitor::visit))
		.def("visit_RegexpOr", py::overload_cast<RegexpOr*>(&RegexpVisitor::visit))
		.def("visit_RegexpGroup", py::overload_cast<RegexpGroup*>(&RegexpVisitor::visit))
		.def("visit_RegexpConcat", py::overload_cast<RegexpConcat*>(&RegexpVisitor::visit));

	py::class_<ObservingRegexpVisitor, PyObservingRegexpVisitor, RegexpVisitor>(module, "ObservingRegexpVisitor")
		.def(py::init<>())
		.def("observe", &ObservingRegexpVisitor::observe)
		.def("visit_RegexpClass", py::overload_cast<RegexpClass*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpText", py::overload_cast<RegexpText*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpAnyChar", py::overload_cast<RegexpAnyChar*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpWordChar", py::overload_cast<RegexpWordChar*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpNonWordChar", py::overload_cast<RegexpNonWordChar*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpSpace", py::overload_cast<RegexpSpace*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpNonSpace", py::overload_cast<RegexpNonSpace*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpDigit", py::overload_cast<RegexpDigit*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpNonDigit", py::overload_cast<RegexpNonDigit*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpWordBoundary", py::overload_cast<RegexpWordBoundary*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpNonWordBoundary", py::overload_cast<RegexpNonWordBoundary*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpStartOfLine", py::overload_cast<RegexpStartOfLine*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpEndOfLine", py::overload_cast<RegexpEndOfLine*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpIteration", py::overload_cast<RegexpIteration*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpPositiveIteration", py::overload_cast<RegexpPositiveIteration*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpOptional", py::overload_cast<RegexpOptional*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpRange", py::overload_cast<RegexpRange*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpOr", py::overload_cast<RegexpOr*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpGroup", py::overload_cast<RegexpGroup*>(&ObservingRegexpVisitor::visit))
		.def("visit_RegexpConcat", py::overload_cast<RegexpConcat*>(&ObservingRegexpVisitor::visit));
}
