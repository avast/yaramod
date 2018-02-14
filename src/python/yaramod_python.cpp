#include <algorithm>
#include <iterator>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <yaramod/builder/yara_expression_builder.h>
#include <yaramod/builder/yara_rule_builder.h>
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

	py::enum_<IntMultiplier>(module, "IntMultiplier")
		.value("None", IntMultiplier::None)
		.value("Kilobytes", IntMultiplier::Kilobytes)
		.value("Megabytes", IntMultiplier::Megabytes);

	py::enum_<Rule::Modifier>(module, "RuleModifier")
		.value("None", Rule::Modifier::None)
		.value("Global", Rule::Modifier::Global)
		.value("Private", Rule::Modifier::Private);

	py::enum_<String::Modifiers>(module, "StringModifiers", py::arithmetic())
		.value("None", String::Modifiers::None)
		.value("Ascii", String::Modifiers::Ascii)
		.value("Wide", String::Modifiers::Wide)
		.value("Nocase", String::Modifiers::Nocase)
		.value("Fullword", String::Modifiers::Fullword)
		.export_values();
}

void addBasicClasses(py::module& module)
{
	py::class_<YaraFile>(module, "YaraFile")
		.def_property_readonly("text", &YaraFile::getText)
		.def_property_readonly("rules", &YaraFile::getRules)
		.def_property_readonly("imports", &YaraFile::getImports);

	py::class_<Rule, std::shared_ptr<Rule>>(module, "Rule")
		.def_property_readonly("text", &Rule::getText)
		.def_property_readonly("name", &Rule::getName)
		.def_property_readonly("metas", &Rule::getMetas)
		.def_property_readonly("condition", &Rule::getCondition);

	py::class_<Meta>(module, "Meta")
		.def_property_readonly("key", &Meta::getKey)
		.def_property_readonly("value", &Meta::getValue);

	py::class_<Literal>(module, "Literal")
		.def_property_readonly("text", &Literal::getText)
		.def_property_readonly("pure_text", &Literal::getPureText);

	py::class_<Module, std::shared_ptr<Module>>(module, "Module")
		.def_property_readonly("name", &Module::getName);
}

void addExpressionClasses(py::module& module)
{
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

void addBuilderClasses(py::module& module)
{
	py::class_<YaraFileBuilder>(module, "YaraFileBuilder")
		.def(py::init<>())
		.def("get", &YaraFileBuilder::get, py::arg("recheck") = false)
		.def("with_module", &YaraFileBuilder::withModule)
		.def("with_rule", [](YaraFileBuilder& self, const Rule& rule) {
				return self.withRule(Rule{rule});
			});

	py::class_<YaraRuleBuilder>(module, "YaraRuleBuilder")
		.def(py::init<>())
		.def("get", [](YaraRuleBuilder& self) {
				// We use unique_ptr in YaraRuleBuilder::get() but pybind does not support unique_ptrs in return values
				return std::shared_ptr<Rule>(self.get());
			})
		.def("with_name", &YaraRuleBuilder::withName)
		.def("with_modifier", &YaraRuleBuilder::withModifier)
		.def("with_tag", &YaraRuleBuilder::withTag)
		.def("with_string_meta", &YaraRuleBuilder::withStringMeta)
		.def("with_int_meta", &YaraRuleBuilder::withIntMeta)
		.def("with_uint_meta", &YaraRuleBuilder::withUIntMeta)
		.def("with_hex_int_meta", &YaraRuleBuilder::withHexIntMeta)
		.def("with_bool_meta", &YaraRuleBuilder::withBoolMeta)
		.def("with_plain_string", &YaraRuleBuilder::withPlainString, py::arg("id"), py::arg("value"), py::arg("mods") = String::Modifiers::Ascii)
		.def("with_hex_string", &YaraRuleBuilder::withHexString)
		.def("with_regexp", &YaraRuleBuilder::withRegexp, py::arg("id"), py::arg("value"), py::arg("suffix_mods") = "", py::arg("mods") = String::Modifiers::Ascii)
		.def("with_condition", py::overload_cast<const std::shared_ptr<Expression>&>(&YaraRuleBuilder::withCondition));

	py::class_<YaraExpressionBuilder>(module, "YaraExpressionBuilder")
		.def(py::init<>())
		.def(py::init<const std::shared_ptr<Expression>&>())
		.def("get", &YaraExpressionBuilder::get)
		.def("__invert__", &YaraExpressionBuilder::operator~)
		.def("__neg__", py::overload_cast<>(&YaraExpressionBuilder::operator-))
		.def("__eq__", &YaraExpressionBuilder::operator==)
		.def("__neq__", &YaraExpressionBuilder::operator!=)
		.def("__lt__", &YaraExpressionBuilder::operator<)
		.def("__gt__", &YaraExpressionBuilder::operator>)
		.def("__le__", &YaraExpressionBuilder::operator<=)
		.def("__ge__", &YaraExpressionBuilder::operator>=)
		.def("__add__", &YaraExpressionBuilder::operator+)
		.def("__sub__", py::overload_cast<const YaraExpressionBuilder&>(&YaraExpressionBuilder::operator-))
		.def("__mul__", &YaraExpressionBuilder::operator*)
		.def("__truediv__", &YaraExpressionBuilder::operator/)
		.def("__mod__", &YaraExpressionBuilder::operator%)
		.def("__xor__", &YaraExpressionBuilder::operator^)
		.def("__and__", &YaraExpressionBuilder::operator&)
		.def("__or__", &YaraExpressionBuilder::operator|)
		.def("__lshift__", &YaraExpressionBuilder::operator<<)
		.def("__rshift__", &YaraExpressionBuilder::operator>>)
		.def("__call__", [](YaraExpressionBuilder& self, py::args args) {
				std::vector<YaraExpressionBuilder> call_args;
				std::transform(args.begin(), args.end(), std::back_inserter(call_args),
						[](const auto& obj) {
							return py::cast<YaraExpressionBuilder>(obj);
						});
				return self.call(call_args);
			})
		.def("__getitem__", &YaraExpressionBuilder::operator[])
		.def("access", &YaraExpressionBuilder::access)
		.def("contains", &YaraExpressionBuilder::contains)
		.def("matches", &YaraExpressionBuilder::matches)
		.def("read_int8", &YaraExpressionBuilder::readInt8)
		.def("read_int16", &YaraExpressionBuilder::readInt16)
		.def("read_int32", &YaraExpressionBuilder::readInt32)
		.def("read_uint8", &YaraExpressionBuilder::readUInt8)
		.def("read_uint16", &YaraExpressionBuilder::readUInt16)
		.def("read_uint32", &YaraExpressionBuilder::readUInt32);

	module.def("not_", [](YaraExpressionBuilder& exprBuilder) {
				return !exprBuilder;
			});

	module.def("int_val", &intVal, py::arg("value"), py::arg("mult") = IntMultiplier::None);
	module.def("uint_val", &uintVal, py::arg("value"), py::arg("mult") = IntMultiplier::None);
	module.def("hex_int_val", &hexIntVal);
	module.def("string_val", &stringVal);
	module.def("bool_val", &boolVal);

	module.def("id", &id);
	module.def("paren", &paren);

	module.def("string_ref", &stringRef);
	module.def("match_count", py::overload_cast<const std::string&>(&matchCount));
	module.def("match_length", py::overload_cast<const std::string&>(&matchLength));
	module.def("match_offset", py::overload_cast<const std::string&>(&matchOffset));
	module.def("match_length", py::overload_cast<const std::string&, const YaraExpressionBuilder&>(&matchLength));
	module.def("match_offset", py::overload_cast<const std::string&, const YaraExpressionBuilder&>(&matchOffset));
	module.def("match_at", py::overload_cast<const std::string&, const YaraExpressionBuilder&>(&matchAt));
	module.def("match_in_range", py::overload_cast<const std::string&, const YaraExpressionBuilder&>(&matchInRange));

	module.def("for_loop", py::overload_cast<
			const YaraExpressionBuilder&,
			const std::string&,
			const YaraExpressionBuilder&,
			const YaraExpressionBuilder&
		>(&forLoop));
	module.def("for_loop", py::overload_cast<
			const YaraExpressionBuilder&,
			const YaraExpressionBuilder&,
			const YaraExpressionBuilder&
		>(&forLoop));
	module.def("of", &of);

	module.def("set", &set);
	module.def("range", &range);

	module.def("conjunction", py::overload_cast<const std::vector<YaraExpressionBuilder>&, bool>(&conjunction), py::arg("terms"), py::arg("linebreaks") = false);
	module.def("disjunction", py::overload_cast<const std::vector<YaraExpressionBuilder>&, bool>(&disjunction), py::arg("terms"), py::arg("linebreaks") = false);

	module.def("filesize", &filesize);
	module.def("entrypoint", &entrypoint);
	module.def("all", &all);
	module.def("any", &any);
	module.def("them", &them);

	module.def("regexp", &regexp);
}

void addMainFunctions(py::module& module)
{
	module.def("parse_file", &parseFile);
	module.def("parse_stream", &parseStream);
}

PYBIND11_MODULE(yaramod, module)
{
	addEnums(module);
	addBasicClasses(module);
	addExpressionClasses(module);
	addMainFunctions(module);
	addVisitorClasses(module);
	addBuilderClasses(module);
}
