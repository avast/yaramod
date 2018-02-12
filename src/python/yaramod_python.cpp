#include <algorithm>
#include <iterator>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <yaramod/yaramod.h>

#include "py_visitor.h"

namespace py = pybind11;
using namespace py::literals;

using namespace yaramod;

namespace pybind11 { namespace detail {

template<>
struct type_caster<std::vector<Rule*>> : list_caster<std::vector<Rule*>, Rule*>
{
	static handle cast(const std::vector<Rule*>& src, return_value_policy, handle parent)
	{
		return list_caster<std::vector<Rule*>, Rule*>::cast(src, return_value_policy::reference, parent);
	}

	static handle cast(const std::vector<Rule*>* src, return_value_policy pol, handle parent)
	{
		return cast(*src, pol, parent);
	}
};

}}

template <typename ExprType, typename ParentType = Expression>
decltype(auto) exprClass(py::module& module, const std::string& name)
{
	return py::class_<ExprType, ParentType, std::shared_ptr<ExprType>>(module, name.c_str());
}

template <typename ExprType>
decltype(auto) unaryOpClass(py::module& module, const std::string& name)
{
	return exprClass<ExprType, UnaryOpExpression>(module, name);
}

template <typename ExprType>
decltype(auto) keywordClass(py::module& module, const std::string& name)
{
	return exprClass<ExprType, KeywordExpression>(module, name);
}

template <typename ExprType>
decltype(auto) binaryOpClass(py::module& module, const std::string& name)
{
	return exprClass<ExprType, BinaryOpExpression>(module, name);
}

void addEnums(py::module& module)
{
	py::enum_<ParserMode>(module, "ParserMode")
		.value("Regular", ParserMode::Regular)
		.value("IncludeGuarded", ParserMode::IncludeGuarded);
}

void addClasses(py::module& module)
{
	py::class_<YaraFile>(module, "YaraFile")
		.def_property_readonly("rules",
				[](const YaraFile& self) {
					// It is impossible to return vector of unique_ptrs in pybind11 so we need to transform it
					// into vector of pointer and let Python make its own copy.
					std::vector<Rule*> result;
					std::transform(self.getRules().begin(), self.getRules().end(), std::back_inserter(result),
							[](const auto& rule) {
								return rule.get();
							});
					return result;
				}, py::return_value_policy::reference);

	py::class_<Rule>(module, "Rule")
		.def_property_readonly("name", &Rule::getName)
		.def_property_readonly("metas", &Rule::getMetas)
		.def_property_readonly("condition", &Rule::getCondition);

	py::class_<Meta>(module, "Meta")
		.def_property_readonly("key", &Meta::getKey)
		.def_property_readonly("value", &Meta::getValue);

	py::class_<Literal>(module, "Literal")
		.def_property_readonly("text", &Literal::getText)
		.def_property_readonly("pure_text", &Literal::getPureText);

	py::class_<Visitee, std::shared_ptr<Visitee>>(module, "Visitee")
		.def("accept", &Visitee::accept);
	py::class_<Expression, Visitee, std::shared_ptr<Expression>>(module, "Expression")
		.def("get_text", &Expression::getText, py::arg("indent") = std::string{})
		.def_property_readonly("text",
				// getText() has default parameter and Python can't deal with it
				[](const Expression* self) {
					return self->getText();
				});

	exprClass<StringExpression>(module, "StringExpression");
	exprClass<StringWildcardExpression>(module, "StringWildcardExpression");
	exprClass<StringAtExpression>(module, "StringAtExpression")
		.def_property_readonly("at_expr", &StringAtExpression::getAtExpression);
	exprClass<StringInRangeExpression>(module, "StringInRangeExpression")
		.def_property_readonly("range_expr", &StringInRangeExpression::getRangeExpression);
	exprClass<StringCountExpression>(module, "StringCountExpression");
	exprClass<StringOffsetExpression>(module, "StringOffsetExpression")
		.def_property_readonly("index_expr", &StringOffsetExpression::getIndexExpression);
	exprClass<StringLengthExpression>(module, "StringLengthExpression")
		.def_property_readonly("index_expr", &StringLengthExpression::getIndexExpression);

	exprClass<UnaryOpExpression>(module, "UnaryOpExpression")
		.def_property("operand", &UnaryOpExpression::getOperand, &UnaryOpExpression::setOperand);
	unaryOpClass<NotExpression>(module, "NotExpression");
	unaryOpClass<UnaryMinusExpression>(module, "UnaryMinusExpression");
	unaryOpClass<BitwiseNotExpression>(module, "BitwiseNotExpression");

	exprClass<BinaryOpExpression>(module, "BinaryOpExpression")
		.def_property("left_operand", &BinaryOpExpression::getLeftOperand, &BinaryOpExpression::setLeftOperand)
		.def_property("right_operand", &BinaryOpExpression::getRightOperand, &BinaryOpExpression::setRightOperand);
	binaryOpClass<AndExpression>(module, "AndExpression");
	binaryOpClass<OrExpression>(module, "OrExpression");
	binaryOpClass<LtExpression>(module, "LtExpression");
	binaryOpClass<GtExpression>(module, "GtExpression");
	binaryOpClass<LeExpression>(module, "LeExpression");
	binaryOpClass<GeExpression>(module, "GeExpression");
	binaryOpClass<EqExpression>(module, "EqExpression");
	binaryOpClass<NeqExpression>(module, "NeqExpression");
	binaryOpClass<ContainsExpression>(module, "ContainsExpression");
	binaryOpClass<MatchesExpression>(module, "MatchesExpression");
	binaryOpClass<PlusExpression>(module, "PlusExpression");
	binaryOpClass<MinusExpression>(module, "MinusExpression");
	binaryOpClass<MultiplyExpression>(module, "MultiplyExpression");
	binaryOpClass<DivideExpression>(module, "DivideExpression");
	binaryOpClass<ModuloExpression>(module, "ModuloExpression");
	binaryOpClass<BitwiseXorExpression>(module, "BitwiseXorExpression");
	binaryOpClass<BitwiseAndExpression>(module, "BitwiseAndExpression");
	binaryOpClass<BitwiseOrExpression>(module, "BitwiseOrExpression");
	binaryOpClass<ShiftLeftExpression>(module, "ShiftLeftExpression");
	binaryOpClass<ShiftRightExpression>(module, "ShiftRightExpression");

	exprClass<ForExpression>(module, "ForExpression")
		.def_property_readonly("variable", &ForExpression::getVariable)
		.def_property_readonly("iterated_set", &ForExpression::getIteratedSet)
		.def_property_readonly("body", &ForExpression::getBody);
	exprClass<ForIntExpression, ForExpression>(module, "ForIntExpression");
	exprClass<ForStringExpression, ForExpression>(module, "ForStringExpression");
	exprClass<OfExpression, ForExpression>(module, "OfExpression");

	exprClass<SetExpression>(module, "SetExpression")
		.def_property("elements", &SetExpression::getElements, &SetExpression::setElements);
	exprClass<RangeExpression>(module, "RangeExpression")
		.def_property_readonly("low", &RangeExpression::getLow)
		.def_property_readonly("high", &RangeExpression::getHigh);
	exprClass<IdExpression>(module, "IdExpression")
		.def_property("symbol", &IdExpression::getSymbol, &IdExpression::setSymbol);
	exprClass<StructAccessExpression, IdExpression>(module, "StructAccessExpression")
		.def_property_readonly("structure", &StructAccessExpression::getStructure);
	exprClass<ArrayAccessExpression, IdExpression>(module, "ArrayAccessExpression")
		.def_property_readonly("array", &ArrayAccessExpression::getArray)
		.def_property_readonly("accessor", &ArrayAccessExpression::getAccessor);
	exprClass<FunctionCallExpression, IdExpression>(module, "FunctionCallExpression")
		.def_property_readonly("function", &FunctionCallExpression::getFunction)
		.def_property("arguments", &FunctionCallExpression::getArguments, &FunctionCallExpression::setArguments);

	exprClass<LiteralExpression<bool>>(module, "_BoolLiteralExpression");
	exprClass<LiteralExpression<std::string>>(module, "_StringLiteralExpression");
	exprClass<BoolLiteralExpression, LiteralExpression<bool>>(module, "BoolLiteralExpression");
	exprClass<StringLiteralExpression, LiteralExpression<std::string>>(module, "StringLiteralExpression");
	exprClass<IntLiteralExpression, LiteralExpression<std::string>>(module, "IntLiteralExpression");
	exprClass<DoubleLiteralExpression, LiteralExpression<std::string>>(module, "DoubleLiteralExpression");

	exprClass<KeywordExpression>(module, "KeywordExpression");
	keywordClass<FilesizeExpression>(module, "FilesizeExpression");
	keywordClass<EntrypointExpression>(module, "EntrypointExpression");
	keywordClass<AllExpression>(module, "AllExpression");
	keywordClass<AnyExpression>(module, "AnyExpression");
	keywordClass<ThemExpression>(module, "ThemExpression");

	exprClass<ParenthesesExpression>(module, "ParenthesesExpression")
		.def_property("enclosed_expr", &ParenthesesExpression::getEnclosedExpression, &ParenthesesExpression::setEnclosedExpression);
	exprClass<IntFunctionExpression>(module, "IntFunctionExpression")
		.def_property_readonly("argument", &IntFunctionExpression::getArgument);
	exprClass<RegexpExpression>(module, "RegexpExpression")
		.def_property_readonly("regexp_string", &RegexpExpression::getRegexpString);
}

void addMainFunctions(py::module& module)
{
	module.def("parse_file", &parseFile);
	module.def("parse_stream", &parseStream);
}

PYBIND11_MODULE(yaramod, module)
{
	addEnums(module);
	addClasses(module);
	addMainFunctions(module);
	addVisitorClasses(module);
}
