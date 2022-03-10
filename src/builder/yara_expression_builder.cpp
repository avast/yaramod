/**
 * @file src/builder/yara_expression_builder.cpp
 * @brief Implementation of class YaraExpressionBuilder.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/builder/yara_expression_builder.h"
#include "yaramod/types/expressions.h"
#include "yaramod/types/regexp.h"
#include "yaramod/types/symbols.h"
#include "yaramod/utils/utils.h"

namespace yaramod {

namespace {

enum class ArgType {Left, Right, Single};
void error_handle(ArgType operator_type, const std::string& op, const std::string& expected_type, const Expression::Ptr& expr)
{
	if (operator_type == ArgType::Single)
		throw YaraExpressionBuilderError("Operator " + op + " type mismatch: Expecting " + expected_type + ", argument '" + expr->getText() + "' has type " + expr->getTypeString() + ".");
	else if (operator_type == ArgType::Right)
		throw YaraExpressionBuilderError("Operator " + op + " type mismatch: Expecting " + expected_type + ", right argument '" + expr->getText() + "' has type " + expr->getTypeString() + ".");
	else
		throw YaraExpressionBuilderError("Operator " + op + " type mismatch: Expecting " + expected_type + ", left argument '" + expr->getText() + "' has type " + expr->getTypeString() + ".");
}

void error_handle(const std::string& msg)
{
	throw YaraExpressionBuilderError(msg);
}

template <typename Op>
YaraExpressionBuilder logicalFormula(std::vector<YaraExpressionBuilder> terms, const Op& op)
{
	if (terms.empty())
		return boolVal(true);

	if (terms.size() == 1)
		return terms.front();

	auto formula = op(terms[0], terms[1]);
	for (std::size_t i = 2; i < terms.size(); ++i)
	{
		if (!terms[i].canBeBool())
		{
			const auto& expr = terms[i].get();
			error_handle("Expected boolean, got '" + expr->getText() + "' of type " + expr->getTypeString());
		}
		if (i >= 2)
			formula = op(formula, terms[i]);
	}

	formula.setType(Expression::Type::Bool);
	return formula;
}

template <typename Op>
YaraExpressionBuilder logicalFormula(std::vector<YaraExpressionBuilder> terms, std::vector<std::string> comments, const Op& op)
{
	if (terms.empty())
		return boolVal(true);

	if (terms.size() == 1)
		return terms.front();

	auto formula = op(terms[0], comments[0], terms[1]);
	for (std::size_t i = 2; i < terms.size(); ++i)
	{
		if (!terms[i].canBeBool())
		{
			const auto& expr = terms[i].get();
			error_handle("Expected boolean, got '" + expr->getText() + "' of type " + expr->getTypeString());
		}
		if (i >= 2)
			formula = op(formula, comments[i-1], terms[i]);
	}

	formula.setType(Expression::Type::Bool);
	return formula;
}

} //namespace

/**
 * Returns the built condition expression and resets the builder back to default state.
 *
 * @return Built condition expression.
 */
Expression::Ptr YaraExpressionBuilder::get() const
{
	_expr->setTokenStream(_tokenStream);
	return _expr;
}

/**
 * Applies negation on the expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator!()
{
	TokenIt token = _tokenStream->emplace(_tokenStream->begin(), TokenType::NOT, "not");
	_expr = std::make_shared<NotExpression>(token, std::move(_expr));
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise not on the expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator~()
{
	TokenIt token = _tokenStream->emplace(_tokenStream->begin(), TokenType::BITWISE_NOT, "~");
	_expr = std::make_shared<BitwiseNotExpression>(token, std::move(_expr));
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies unary minus on the expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator-()
{
	TokenIt token = _tokenStream->emplace(_tokenStream->begin(), TokenType::UNARY_MINUS, "-");
	_expr = std::make_shared<UnaryMinusExpression>(token, std::move(_expr));
	return *this;
}

/**
 * Applies logical and on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator&&(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::AND, "and");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<AndExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies logical or on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator||(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::OR, "or");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<OrExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies less than on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator<(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::LT, "<");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<LtExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies less than or equal on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator<=(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::LE, "<=");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<LeExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies greater than on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator>(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::GT, ">");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<GtExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies greater than or equal on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator>=(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::GE, ">=");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<GeExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies equals to on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator==(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::EQ, "==");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<EqExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies not equals to on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator!=(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::NEQ, "!=");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<NeqExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies plus on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator+(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();

	TokenIt token = _tokenStream->emplace_back(TokenType::PLUS, "+");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<PlusExpression>(std::move(_expr), token, other.get());
	setType(will_be_float ? Expression::Type::Float : Expression::Type::Int);
	return *this;
}

/**
 * Applies minus on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator-(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();

	TokenIt token = _tokenStream->emplace_back(TokenType::MINUS, "-");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<MinusExpression>(std::move(_expr), token, other.get());
	setType(will_be_float ? Expression::Type::Float : Expression::Type::Int);
	return *this;
}

/**
 * Applies multiplication on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator*(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();

	TokenIt token = _tokenStream->emplace_back(TokenType::MULTIPLY, "*");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<MultiplyExpression>(std::move(_expr), token, other.get());
	setType(will_be_float ? Expression::Type::Float : Expression::Type::Int);
	return *this;
}

/**
 * Applies division on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator/(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();

	TokenIt token = _tokenStream->emplace_back(TokenType::DIVIDE, "\\");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<DivideExpression>(std::move(_expr), token, other.get());
	setType(will_be_float ? Expression::Type::Float : Expression::Type::Int);
	return *this;
}

/**
 * Applies modulo on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator%(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();

	TokenIt token = _tokenStream->emplace_back(TokenType::PERCENT, "%");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<ModuloExpression>(std::move(_expr), token, other.get());
	setType(will_be_float ? Expression::Type::Float : Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise xor on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator^(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::BITWISE_XOR, "^");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<BitwiseXorExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise and on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator&(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::BITWISE_AND, "&");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<BitwiseAndExpression>(std::move(_expr), token, other.get());

	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise or on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator|(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::BITWISE_OR, "|");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<BitwiseOrExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise shift left on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator<<(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::SHIFT_LEFT, "<<");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<ShiftLeftExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise shift right on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator>>(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::SHIFT_RIGHT, ">>");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<ShiftRightExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Calls function from an expression
 *
 * @param args Arguments of the function.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::call(const std::vector<YaraExpressionBuilder>& args)
{
	TokenIt lb = _tokenStream->emplace_back(TokenType::FUNCTION_CALL_LP, "(");
	for (std::size_t i = 0; i < args.size(); ++i)
	{
		_tokenStream->moveAppend(args[i].getTokenStream());
		if (i < args.size() - 1)
			_tokenStream->emplace_back(TokenType::COMMA, ",");
	}
	TokenIt rb = _tokenStream->emplace_back(TokenType::FUNCTION_CALL_RP, ")");

	std::vector<Expression::Ptr> exprArgs;
	std::for_each(args.begin(), args.end(), [&exprArgs](const YaraExpressionBuilder& expr) {
		exprArgs.push_back(expr.get());
		assert(exprArgs.back());
	});
	_expr = std::make_shared<FunctionCallExpression>(std::move(_expr), lb, std::move(exprArgs), rb);
	return *this;
}

/**
 * Puts comment in front of the expression.
 *
 * @param message The comment message.
 * @param multiline If set, the commet will be multiline.
 * @param indent Additional indent added to the indentation computed by the autoformatter.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::comment(const std::string& message, bool multiline, const std::string& indent, bool linebreak)
{
	_tokenStream->comment(message, multiline, indent, linebreak);
	return *this;
}

/**
 * Puts comment behind the expression.
 *
 * @param message The comment message.
 * @param multiline If set, the commet will be multiline.
 * @param indent Additional indent added to the indentation computed by the autoformatter.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::commentBehind(const std::string& message, bool multiline, const std::string& indent, bool linebreak)
{
	_tokenStream->commentBehind(message, multiline, indent, linebreak);
	return *this;
}

/**
 * Applies operation contains on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::contains(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::CONTAINS, "contains");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<ContainsExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies operation matches on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::matches(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::MATCHES, "matches");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<MatchesExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies operation iequals on two expressions.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::iequals(const YaraExpressionBuilder& other)
{
	TokenIt token = _tokenStream->emplace_back(TokenType::IEQUALS, "iequals");
	_tokenStream->moveAppend(other.getTokenStream());

	_expr = std::make_shared<IequalsExpression>(std::move(_expr), token, other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies operation defined on the expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::defined() {
	auto token = _tokenStream->emplace(_tokenStream->begin(), TokenType::DEFINED, "defined");
	_expr = std::make_shared<DefinedExpression>(token, std::move(_expr));
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies operation percent on the expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::percent() {
	auto token = _tokenStream->emplace_back(TokenType::PERCENT, "%");
	_expr = std::make_shared<PercentualExpression>(std::move(_expr), token);
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Accesses the attribute of a structure expression.
 *
 * @param attr Name of attribute.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::access(const std::string& attr) // pe.attr
{
	TokenIt dotIt = _tokenStream->emplace_back(TokenType::DOT, ".");
	const std::shared_ptr<Symbol>& symbol = std::make_shared<ValueSymbol>(attr, Expression::Type::Object);
	Expression::Type type = symbol->getDataType();
	TokenIt symbolIt = _tokenStream->emplace_back(TokenType::ID, std::move(symbol));

	_expr = std::make_shared<StructAccessExpression>(std::move(_expr), dotIt, symbolIt);
	setType(type);
	return *this;
}

/**
 * Accesses the array index or dictionary index of an array or dictionary expression.
 *
 * @param other The accessor expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator[](const YaraExpressionBuilder& other)
{
	TokenIt lsqb = _tokenStream->emplace_back(TokenType::LSQB, "[");
	_tokenStream->moveAppend(other.getTokenStream());
	TokenIt rsqb = _tokenStream->emplace_back(TokenType::RSQB, "]");

	_expr = std::make_shared<ArrayAccessExpression>(std::move(_expr), lsqb, std::move(other.get()), rsqb);
	setType(Expression::Type::Undefined);
	return *this;
}

/**
 * Applies integer function int8(be)? on the expression.
 *
 * @param bigEndian @c true if big-endian version should be used.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::readInt8(IntFunctionEndianness endianness)
{
	return readIntegerFunction(endianness == IntFunctionEndianness::Big ? "int8be" : "int8");
}

/**
 * Applies integer function int16(be)? on the expression.
 *
 * @param endianness == IntFunctionEndianness::Big @c true if big-endian version should be used.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::readInt16(IntFunctionEndianness endianness)
{
	return readIntegerFunction(endianness == IntFunctionEndianness::Big ? "int16be" : "int16");
}

/**
 * Applies integer function int32(be)? on the expression.
 *
 * @param endianness == IntFunctionEndianness::Big @c true if big-endian version should be used.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::readInt32(IntFunctionEndianness endianness)
{
	return readIntegerFunction(endianness == IntFunctionEndianness::Big ? "int32be" : "int32");
}

/**
 * Applies integer function uint8(be)? on the expression.
 *
 * @param endianness == IntFunctionEndianness::Big @c true if big-endian version should be used.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::readUInt8(IntFunctionEndianness endianness)
{
	return readIntegerFunction(endianness == IntFunctionEndianness::Big ? "uint8be" : "uint8");
}

/**
 * Applies integer function uint16(be)? on the expression.
 *
 * @param endianness == IntFunctionEndianness::Big @c true if big-endian version should be used.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::readUInt16(IntFunctionEndianness endianness)
{
	return readIntegerFunction(endianness == IntFunctionEndianness::Big ? "uint16be" : "uint16");
}

/**
 * Applies integer function uint32(be)? on the expression.
 *
 * @param bigEndian @c true if big-endian version should be used.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::readUInt32(IntFunctionEndianness endianness)
{
	return readIntegerFunction(endianness == IntFunctionEndianness::Big ? "uint32be" : "uint32");
}

YaraExpressionBuilder& YaraExpressionBuilder::readIntegerFunction(const std::string& function_name)
{
	TokenIt lb = _tokenStream->emplace(_tokenStream->begin(), TokenType::LP, "(");
	TokenIt func = _tokenStream->emplace(_tokenStream->begin(), TokenType::INTEGER_FUNCTION, std::move(function_name));
	TokenIt rb = _tokenStream->emplace_back(TokenType::RP, ")");

	_expr = std::make_shared<IntFunctionExpression>(func, lb, std::move(_expr), rb);
	setType(Expression::Type::Int);

	return *this;
}

/**
 * Creates the integer expression from a number and multiplier.
 *
 * @param value Integer value.
 * @param mult Used multiplier.
 *
 * @return Builder.
 */
YaraExpressionBuilder intVal(std::int64_t value, IntMultiplier mult)
{
	std::string strValue = numToStr(value);
	switch (mult)
	{
		case IntMultiplier::Kilobytes:
			strValue += "KB";
			break;
		case IntMultiplier::Megabytes:
			strValue += "MB";
			break;
		default:
			break;
	}
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::INTEGER, value, std::move(strValue));
	auto expression = std::make_shared<IntLiteralExpression>(token);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Int);
}

/**
 * Creates the unsigned integer expression from a number and multiplier.
 *
 * @param value Integer value.
 * @param mult Used multiplier.
 *
 * @return Builder.
 */
YaraExpressionBuilder uintVal(std::uint64_t value, IntMultiplier mult)
{
	return intVal(value, mult);
}

/**
 * Creates the hexadecimal integer expression from a number.
 *
 * @param value Integer value.
 *
 * @return Builder.
 */
YaraExpressionBuilder hexIntVal(std::uint64_t value)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::INTEGER, value, numToStr(value, std::hex, true));
	auto expression = std::make_shared<IntLiteralExpression>(token);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Int);
}

/**
 * Creates the double expression from a number.
 *
 * @param value Double value.
 *
 * @return Builder.
 */
YaraExpressionBuilder doubleVal(double value)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::DOUBLE, value, numToStr(value));
	auto expression = std::make_shared<DoubleLiteralExpression>(token);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Float);
}

/**
 * Creates the string expression.
 *
 * @param value String value.
 *
 * @return Builder.
 */
YaraExpressionBuilder stringVal(const std::string& value)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::STRING_LITERAL, escapeString(value));
	token->markEscaped();
	auto expression = std::make_shared<StringLiteralExpression>(token);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::String);
}

/**
 * Creates the boolean expression:
 *
 * @param value Boolean value.
 *
 * @return Builder.
 */
YaraExpressionBuilder boolVal(bool value)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(value ? TokenType::BOOL_TRUE : TokenType::BOOL_FALSE, value);
	auto expression = std::make_shared<BoolLiteralExpression>(token);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates the expression referencing other symbol (rule, for loop identifier or module structure).
 *
 * @param id Identifier to reference.
 *
 * @return Builder.
 */
YaraExpressionBuilder id(const std::string& id)
{
	auto ts = std::make_shared<TokenStream>();
	const std::shared_ptr<Symbol>& symbol = std::make_shared<ValueSymbol>(id, Expression::Type::Object);
	TokenIt token = ts->emplace_back(TokenType::ID, std::move(symbol));
	auto expression = std::make_shared<IdExpression>(token);
	return YaraExpressionBuilder(std::move(ts), std::move(expression));
}

/**
 * Creates the expression enclosed in parentheses.
 *
 * @param other The expression to enclose.
 * @param linebreak Put linebreak after opening and before closing parenthesis and indent content by one more level.
 *
 * @return Builder.
 */
YaraExpressionBuilder paren(const YaraExpressionBuilder& other, bool linebreak)
{
	auto ts = std::make_shared<TokenStream>();
	auto lb = ts->emplace_back(TokenType::LP, "(");
	if (linebreak)
		ts->emplace_back(TokenType::NEW_LINE, "\n");
	ts->moveAppend(other.getTokenStream());
	if (linebreak)
		ts->emplace_back(TokenType::NEW_LINE, "\n");
	auto rb = ts->emplace_back(TokenType::RP, ")");
	auto expression = std::make_shared<ParenthesesExpression>(lb, other.get(), rb, linebreak);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), other.getType());
}

/**
 * Creates the expression with reference to string identifier.
 *
 * @param id String identifier.
 *
 * @return Builder.
 */
YaraExpressionBuilder stringRef(const std::string& id)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::STRING_ID, id);
	if (endsWith(id, '*'))
		return YaraExpressionBuilder(std::move(ts), std::make_shared<StringWildcardExpression>(token));
	else
		return YaraExpressionBuilder(std::move(ts), std::make_shared<StringExpression>(token), Expression::Type::Bool);
}

/**
 * Creates the expression with reference to match count of particular string.
 *
 * @param id String identifier.
 *
 * @return Builder.
 */
YaraExpressionBuilder matchCount(const std::string& id)
{
	assert(!id.empty() && (id[0] == '$' || id[0] == '#'));

	// Replace '$' with '#'
	auto countId = id;
	countId[0] = '#';

	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::STRING_COUNT, std::move(countId));
	auto expression = std::make_shared<StringCountExpression>(token);

	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Int);
}

/**
 * Creates the expression with reference to first match length of particular string.
 *
 * @param id String identifier.
 *
 * @return Builder.
 */
YaraExpressionBuilder matchLength(const std::string& id)
{
	assert(!id.empty() && (id[0] == '$' || id[0] == '!'));

	// Replace '$' with '!'
	auto lengthId = id;
	lengthId[0] = '!';

	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::STRING_LENGTH, std::move(lengthId));
	auto expression = std::make_shared<StringLengthExpression>(token);

	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Int);
}

/**
 * Creates the expression with reference to first match offset of particular string.
 *
 * @param id String identifier.
 *
 * @return Builder.
 */
YaraExpressionBuilder matchOffset(const std::string& id)
{
	assert(!id.empty() && (id[0] == '$' || id[0] == '@'));

	// Replace '$' with '@'
	auto offsetId = id;
	offsetId[0] = '@';

	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::STRING_OFFSET, std::move(offsetId));
	auto expression = std::make_shared<StringOffsetExpression>(token);

	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Int);
}

/**
 * Creates the expression with reference to Nth match length of particular string.
 *
 * @param id String identifier.
 * @param other Accessor to Nth match length.
 *
 * @return Builder.
 */
YaraExpressionBuilder matchLength(const std::string& id, const YaraExpressionBuilder& other)
{
	assert(!id.empty() && (id[0] == '$' || id[0] == '!'));

	// Replace '$' with '!'
	auto lengthId = id;
	lengthId[0] = '!';

	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::STRING_LENGTH, std::move(lengthId));
	auto other_expression = other.get();
	ts->emplace_back(TokenType::LSQB, "[");
	ts->moveAppend(other_expression->getTokenStream());
	ts->emplace_back(TokenType::RSQB, "]");
	auto expression = std::make_shared<StringLengthExpression>(token, std::move(other_expression));

	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Int);
}

/**
 * Creates the expression with reference to Nth match offset of particular string.
 *
 * @param id String identifier.
 * @param other Accessor to Nth match offset.
 *
 * @return Builder.
 */
YaraExpressionBuilder matchOffset(const std::string& id, const YaraExpressionBuilder& other)
{
	assert(!id.empty() && (id[0] == '$' || id[0] == '@'));

	// Replace '$' with '@'
	auto offsetId = id;
	offsetId[0] = '@';

	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::STRING_OFFSET, std::move(offsetId));
	auto other_expression = other.get();
	ts->emplace_back(TokenType::LSQB, "[");
	ts->moveAppend(other_expression->getTokenStream());
	ts->emplace_back(TokenType::RSQB, "]");
	auto expression = std::make_shared<StringOffsetExpression>(token, std::move(other_expression));

	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Int);
}

/**
 * Creates the expression with match of the string at given offset.
 *
 * @param id String identifier.
 * @param other Offset expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder matchAt(const std::string& id, const YaraExpressionBuilder& other)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt id_token = ts->emplace_back(TokenType::STRING_ID, id);
	TokenIt at_symbol = ts->emplace_back(TokenType::OP_AT, "at");

	auto other_expression = other.get();
	ts->moveAppend(other_expression->getTokenStream());

	auto expression = std::make_shared<StringAtExpression>(id_token, at_symbol, std::move(other_expression));
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates the expression with match of the string in given range.
 *
 * @param id String identifier.
 * @param other Range expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder matchInRange(const std::string& id, const YaraExpressionBuilder& other)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt id_token = ts->emplace_back(TokenType::STRING_ID, id);
	TokenIt in_symbol = ts->emplace_back(TokenType::OP_IN, "in");

	auto other_expression = other.get();
	ts->moveAppend(other_expression->getTokenStream());
	auto expression = std::make_shared<StringInRangeExpression>(id_token, in_symbol, std::move(other_expression));

	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates the for loop expression over dictionary using two iterating variable with given names.
 *
 * @param forExpr Expression specifying requirement of the for loop.
 * @param id1 Name of the first iterating variable.
 * @param id2 Name of the second iterating variable.
 * @param dict Dictionary.
 * @param expr Body of the for loop.
 *
 * @return Builder.
 */
YaraExpressionBuilder forLoop(const YaraExpressionBuilder& forExpr, const std::string& id1, const std::string& id2, const YaraExpressionBuilder& dict, const YaraExpressionBuilder& expr)
{
	auto ts = std::make_shared<TokenStream>();
	auto forToken = ts->emplace_back(TokenType::FOR, "for");
	ts->moveAppend(forExpr.getTokenStream());
	auto id1Token = ts->emplace_back(TokenType::ID, id1);
	auto commaToken = ts->emplace_back(TokenType::COMMA, ",");
	auto id2Token = ts->emplace_back(TokenType::ID, id2);
	auto inToken = ts->emplace_back(TokenType::OP_IN, "in");
	ts->moveAppend(dict.getTokenStream());
	ts->emplace_back(TokenType::COLON, ":");
	auto lb = ts->emplace_back(TokenType::LP_WITH_SPACE_AFTER, "(");
	ts->moveAppend(expr.getTokenStream());
	auto rb = ts->emplace_back(TokenType::RP_WITH_SPACE_BEFORE, ")");

	auto expression = std::make_shared<ForDictExpression>(forToken, forExpr.get(), id1Token, commaToken, id2Token, inToken, dict.get(), lb, expr.get(), rb);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates the for loop expression over set of integers or array using iterating variable with given name.
 *
 * @param forExpr Expression specifying requirement of the for loop.
 * @param id Name of the iterating variable.
 * @param iterable Set of integers or array.
 * @param expr Body of the for loop.
 *
 * @return Builder.
 */
YaraExpressionBuilder forLoop(const YaraExpressionBuilder& forExpr, const std::string& id, const YaraExpressionBuilder& iterable, const YaraExpressionBuilder& expr)
{
	auto ts = std::make_shared<TokenStream>();
	auto forToken = ts->emplace_back(TokenType::FOR, "for");
	ts->moveAppend(forExpr.getTokenStream());
	auto idToken = ts->emplace_back(TokenType::ID, id);
	auto inToken = ts->emplace_back(TokenType::OP_IN, "in");
	ts->moveAppend(iterable.getTokenStream());
	ts->emplace_back(TokenType::COLON, ":");
	auto lb = ts->emplace_back(TokenType::LP_WITH_SPACE_AFTER, "(");
	ts->moveAppend(expr.getTokenStream());
	auto rb = ts->emplace_back(TokenType::RP_WITH_SPACE_BEFORE, ")");

	auto expression = std::make_shared<ForArrayExpression>(forToken, forExpr.get(), idToken, inToken, iterable.get(), lb, expr.get(), rb);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates the for loop expression over set of string references.
 *
 * @param forExpr Expression specifying requirement of the for loop.
 * @param set Set of string references.
 * @param expr Body of the for loop.
 *
 * @return Builder.
 */
YaraExpressionBuilder forLoop(const YaraExpressionBuilder& forExpr, const YaraExpressionBuilder& set, const YaraExpressionBuilder& expr)
{
	auto ts = std::make_shared<TokenStream>();
	auto forToken = ts->emplace_back(TokenType::FOR, "for");
	ts->moveAppend(forExpr.getTokenStream());
	auto ofToken = ts->emplace_back(TokenType::OF, "of");
	ts->moveAppend(set.getTokenStream());
	ts->emplace_back(TokenType::COLON, ":");
	auto lb = ts->emplace_back(TokenType::LP_WITH_SPACE_AFTER, "(");
	ts->moveAppend(expr.getTokenStream());
	auto rb = ts->emplace_back(TokenType::RP_WITH_SPACE_BEFORE, ")");

	auto expression = std::make_shared<ForStringExpression>(forToken, forExpr.get(), ofToken, set.get(), lb, expr.get(), rb);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates the of expression over set of string references.
 *
 * @param ofExpr Expression specifying requirement of the of operator.
 * @param set Set of string references.
 *
 * @return Builder.
 */
YaraExpressionBuilder of(const YaraExpressionBuilder& ofExpr, const YaraExpressionBuilder& set)
{
	auto ts = std::make_shared<TokenStream>();
	ts->moveAppend(ofExpr.getTokenStream());
	auto ofToken = ts->emplace_back(TokenType::OF, "of");
	ts->moveAppend(set.getTokenStream());

	auto expression = std::make_shared<OfExpression>(ofExpr.get(), ofToken, set.get());
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates the expression with match of the specified set of strings in given range.
 *
 * @param quantifier All / Any / None expression.
 * @param set Set expression.
 * @param range Range expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder of(const YaraExpressionBuilder& quantifier, const YaraExpressionBuilder& set, const YaraExpressionBuilder& range)
{
	auto ts = std::make_shared<TokenStream>();
	ts->moveAppend(quantifier.getTokenStream());
	auto ofToken = ts->emplace_back(TokenType::OF, "of");
	ts->moveAppend(set.getTokenStream());
	auto inToken = ts->emplace_back(TokenType::OP_IN, "in");
	ts->moveAppend(range.getTokenStream());

	auto expression = std::make_shared<OfExpression>(quantifier.get(), ofToken, set.get(), inToken, range.get());

	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates an iterable array of elements.
 *
 * @param elements Elements.
 *
 * @return Builder.
 */
YaraExpressionBuilder iterable(const std::vector<YaraExpressionBuilder>& elements)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt lsqb = ts->emplace_back(TokenType::LSQB_ENUMERATION, "[");
	for (std::size_t i = 0; i < elements.size(); ++i)
	{
		ts->moveAppend(elements[i].getTokenStream());
		if (i < elements.size() - 1)
			ts->emplace_back(TokenType::COMMA, ",");
	}
	TokenIt rsqb = ts->emplace_back(TokenType::RSQB_ENUMERATION, "]");

	std::vector<Expression::Ptr> elementsExprs;
	std::for_each(elements.begin(), elements.end(), [&elementsExprs](const YaraExpressionBuilder& expr) { elementsExprs.push_back(expr.get()); });

	auto expression = std::make_shared<IterableExpression>(lsqb, std::move(elementsExprs), rsqb);
	return YaraExpressionBuilder(std::move(ts), std::move(expression));
}

/**
 * Creates the set of elements.
 *
 * @param elements Elements.
 *
 * @return Builder.
 */
YaraExpressionBuilder set(const std::vector<YaraExpressionBuilder>& elements)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt lb = ts->emplace_back(TokenType::LP, "(");
	for (std::size_t i = 0; i < elements.size(); ++i)
	{
		ts->moveAppend(elements[i].getTokenStream());
		if (i < elements.size() - 1)
			ts->emplace_back(TokenType::COMMA, ",");
	}
	TokenIt rb = ts->emplace_back(TokenType::RP, ")");

	std::vector<Expression::Ptr> elementsExprs;
	std::for_each(elements.begin(), elements.end(), [&elementsExprs](const YaraExpressionBuilder& expr) { elementsExprs.push_back(expr.get()); });

	auto expression = std::make_shared<SetExpression>(lb, std::move(elementsExprs), rb);
	return YaraExpressionBuilder(std::move(ts), std::move(expression));
}

/**
 * Creates conjunction.
 *
 * @param lhs Left-hand side.
 * @param rhs Right-hand side.
 * @param linebreak Put linebreak after operator.
 *
 * @return Builder.
 */
YaraExpressionBuilder conjunction(const YaraExpressionBuilder& lhs, const YaraExpressionBuilder& rhs, bool linebreak)
{
	if (!lhs.canBeBool())
		error_handle(ArgType::Left, "and", "bool", rhs.get());
	else if (!rhs.canBeBool())
		error_handle(ArgType::Right, "and", "bool", lhs.get());

	auto ts = std::make_shared<TokenStream>();
	ts->moveAppend(lhs.getTokenStream());
	TokenIt andToken = ts->emplace_back(TokenType::AND, "and");
	if (linebreak)
		ts->emplace_back(TokenType::NEW_LINE, "\n");
	ts->moveAppend(rhs.getTokenStream());

	auto expression = std::make_shared<AndExpression>(lhs.get(), andToken, rhs.get(), linebreak);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates disjunction.
 *
 * @param lhs Left-hand side.
 * @param rhs Right-hand side.
 * @param linebreak Put linebreak after operator.
 *
 * @return Builder.
 */
YaraExpressionBuilder disjunction(const YaraExpressionBuilder& lhs, const YaraExpressionBuilder& rhs, bool linebreak)
{
	if (!lhs.canBeBool())
		error_handle(ArgType::Left, "or", "bool", lhs.get());
	else if (!rhs.canBeBool())
		error_handle(ArgType::Right, "or", "bool", rhs.get());

	auto ts = std::make_shared<TokenStream>();
	ts->moveAppend(lhs.getTokenStream());
	TokenIt orToken = ts->emplace_back(TokenType::OR, "or");
	if (linebreak)
		ts->emplace_back(TokenType::NEW_LINE, "\n");
	ts->moveAppend(rhs.getTokenStream());

	auto expression = std::make_shared<OrExpression>(lhs.get(), orToken, rhs.get(), linebreak);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates conjunction.
 *
 * @param lhs Left-hand side.
 * @param lhscomment First comment.
 * @param rhs Right-hand side.
 *
 * @return Builder.
 */
YaraExpressionBuilder conjunction(const YaraExpressionBuilder& lhs, const std::string& lhscomment, const YaraExpressionBuilder& rhs)
{
	if (!lhs.canBeBool())
		error_handle(ArgType::Left, "and", "bool", rhs.get());
	else if (!rhs.canBeBool())
		error_handle(ArgType::Right, "and", "bool", lhs.get());

	auto ts = std::make_shared<TokenStream>();
	ts->moveAppend(lhs.getTokenStream());
	TokenIt andToken = ts->emplace_back(TokenType::AND, "and");
	ts->commentBehind(lhscomment, false, "", true);
	ts->moveAppend(rhs.getTokenStream());

	auto expression = std::make_shared<AndExpression>(lhs.get(), andToken, rhs.get(), true);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates disjunction.
 *
 * @param lhs Left-hand side.
 * @param lhscomment First comment.
 * @param rhs Right-hand side.
 *
 * @return Builder.
 */
YaraExpressionBuilder disjunction(const YaraExpressionBuilder& lhs, const std::string& lhscomment, const YaraExpressionBuilder& rhs)
{
	if (!lhs.canBeBool())
		error_handle(ArgType::Left, "or", "bool", lhs.get());
	else if (!rhs.canBeBool())
		error_handle(ArgType::Right, "or", "bool", rhs.get());

	auto ts = std::make_shared<TokenStream>();
	ts->moveAppend(lhs.getTokenStream());
	TokenIt orToken = ts->emplace_back(TokenType::OR, "or");
	ts->commentBehind(lhscomment, false, "", true);
	ts->moveAppend(rhs.getTokenStream());

	auto expression = std::make_shared<OrExpression>(lhs.get(), orToken, rhs.get(), true);
	return YaraExpressionBuilder(std::move(ts), std::move(expression), Expression::Type::Bool);
}

/**
 * Creates conjunction of terms.
 *
 * @param terms Terms of logical formula.
 * @param linebreaks Put linebreaks after operators.
 *
 * @return Builder.
 */
YaraExpressionBuilder conjunction(const std::vector<YaraExpressionBuilder>& terms, bool linebreaks)
{
	for (const auto& bld : terms)
		if (!bld.canBeBool())
			error_handle(ArgType::Single, "and", "bool", bld.get());
	return logicalFormula(terms, [linebreaks](YaraExpressionBuilder& term1, YaraExpressionBuilder& term2) { return conjunction(term1, term2, linebreaks); });
}

/**
 * Creates disjunction of terms.
 *
 * @param terms Terms of logical formula.
 * @param linebreaks Put linebreaks after operators.
 *
 * @return Builder.
 */
YaraExpressionBuilder disjunction(const std::vector<YaraExpressionBuilder>& terms, bool linebreaks)
{
	for (const auto& bld : terms)
		if (!bld.canBeBool())
			error_handle(ArgType::Single, "or", "bool", bld.get());
	return logicalFormula(terms, [linebreaks](YaraExpressionBuilder& term1, YaraExpressionBuilder& term2) { return disjunction(term1, term2, linebreaks); });
}

/**
 * Creates conjunction of terms.
 *
 * @param terms Pairs containing a term of the conjunction and a comment assigned to this term.
 * @param linebreaks Put linebreaks after operators.
 *
 * @return Builder.
 */
YaraExpressionBuilder conjunction(const std::vector<std::pair<YaraExpressionBuilder, std::string>>& commented_terms)
{
	std::vector<YaraExpressionBuilder> terms;
	std::vector<std::string> comments;
	for (const auto& pair : commented_terms)
	{
		if (!pair.first.canBeBool())
			error_handle(ArgType::Single, "and", "bool", pair.first.get());
		terms.push_back(pair.first);
		comments.push_back(pair.second);
	}
	auto output = logicalFormula(terms, comments, []( YaraExpressionBuilder& term1, std::string& comment1, YaraExpressionBuilder& term2) {
		return conjunction(term1, comment1, term2);
	});

	output.commentBehind(comments.back(), false, "", false);
	return output;
}

/**
 * Creates disjunction of terms.
 *
 * @param terms Pairs containing a term of the disjunction and a comment assigned to this term.
 * @param linebreaks Put linebreaks after operators.
 *
 * @return Builder.
 */
YaraExpressionBuilder disjunction(const std::vector<std::pair<YaraExpressionBuilder, std::string>>& commented_terms)
{
	std::vector<YaraExpressionBuilder> terms;
	std::vector<std::string> comments;
	for (const auto& pair : commented_terms)
	{
		if (!pair.first.canBeBool())
			error_handle(ArgType::Single, "and", "bool", pair.first.get());
		terms.push_back(pair.first);
		comments.push_back(pair.second);
	}
	auto output = logicalFormula(terms, comments, []( YaraExpressionBuilder& term1, std::string& comment1, YaraExpressionBuilder& term2) {
		return disjunction(term1, comment1, term2);
	});

	output.commentBehind(comments.back(), false, "", false);
	return output;
}

/**
 * Creates the range with low and high bound.
 *
 * @param low Low bound expression.
 * @param high High bound expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder range(const YaraExpressionBuilder& low, const YaraExpressionBuilder& high)
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt lb = ts->emplace_back(TokenType::LP, "(");
	ts->moveAppend(low.getTokenStream());
	TokenIt opToken = ts->emplace_back(TokenType::DOUBLE_DOT, "..");
	ts->moveAppend(high.getTokenStream());
	TokenIt rb = ts->emplace_back(TokenType::RP, ")");

	auto expression = std::make_shared<RangeExpression>(lb, low.get(), opToken, high.get(), rb);
	return YaraExpressionBuilder(std::move(ts), std::move(expression));
}

/**
 * Creates the expression with keyword @c filesize.
 *
 * @return Builder.
 */
YaraExpressionBuilder filesize()
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::FILESIZE, "filesize");
	return YaraExpressionBuilder(std::move(ts), std::make_shared<FilesizeExpression>(token), Expression::Type::Int);
}

/**
 * Creates the expression with keyword @c entrypoint.
 *
 * @return Builder.
 */
YaraExpressionBuilder entrypoint()
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::ENTRYPOINT, "entrypoint");
	return YaraExpressionBuilder(std::move(ts), std::make_shared<EntrypointExpression>(token), Expression::Type::Int);
}

/**
 * Creates the expression with keyword @c all.
 *
 * @return Builder.
 */
YaraExpressionBuilder all()
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::ALL, "all");
	return YaraExpressionBuilder(std::move(ts), std::make_shared<AllExpression>(token));
}

/**
 * Creates the expression with keyword @c any.
 *
 * @return Builder.
 */
YaraExpressionBuilder any()
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::ANY, "any");
	return YaraExpressionBuilder(std::move(ts), std::make_shared<AnyExpression>(token));
}

/**
 * Creates the expression with keyword @c any.
 *
 * @return Builder.
 */
YaraExpressionBuilder none()
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::NONE, "none");
	return YaraExpressionBuilder(std::move(ts), std::make_shared<NoneExpression>(token));
}

/**
 * Creates the expression with keyword @c them.
 *
 * @return Builder.
 */
YaraExpressionBuilder them()
{
	auto ts = std::make_shared<TokenStream>();
	TokenIt token = ts->emplace_back(TokenType::THEM, "them");
	return YaraExpressionBuilder(std::move(ts), std::make_shared<ThemExpression>(token));
}

/**
 * Creates the expression with regular expression in it from the given text.
 *
 * @param text Textual representation of regular expression.
 * @param suffixMods Suffix modifiers of the regular expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder regexp(const std::string& text, const std::string& suffixMods)
{
	std::shared_ptr<TokenStream> ts = std::make_shared<TokenStream>();
	auto regexp = std::make_shared<Regexp>(ts, std::make_shared<RegexpText>(text));
	regexp->setSuffixModifiers(suffixMods);
	return YaraExpressionBuilder(std::move(ts), std::make_shared<RegexpExpression>(std::move(regexp)), Expression::Type::Regexp);
}

}
