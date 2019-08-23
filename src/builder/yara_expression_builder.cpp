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

#include <iostream>

namespace yaramod {

namespace {

enum class ArgType {Left, Right, Single};
void error_handle(ArgType operator_type, const std::string& op, const std::string& expected_type, const Expression::Ptr& expr)
{
	if(operator_type == ArgType::Single)
		throw YaraExpressionBuilderError("Operator " + op + " type mismatch: Expecting " + expected_type + ", argument '" + expr->getText() + "' has type " + expr->getTypeString() + ".");
	else if(operator_type == ArgType::Right)
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
		return { terms.front().get() };

	auto formula = op(terms[0], terms[1]);
	for (std::size_t i = 2; i < terms.size(); ++i)
	{
		if( !terms[i].canBeBool() ){
			const auto& expr = terms[i].get();
			error_handle( "Expected boolean, got '" + expr->getText() + "' of type " + expr->getTypeString() );
		}
		if( i>=2 )
			formula = op(formula, terms[i]);
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
	return _expr;
}

/**
 * Applies negation on the expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator!()
{
	_expr = std::make_shared<NotExpression>(std::move(_expr));
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
	_expr = std::make_shared<BitwiseNotExpression>(std::move(_expr));
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
	_expr = std::make_shared<UnaryMinusExpression>(std::move(_expr));
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
	_expr = std::make_shared<AndExpression>(std::move(_expr), other.get());
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
	_expr = std::make_shared<OrExpression>(std::move(_expr), other.get());
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
	_expr = std::make_shared<LtExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies less than or equal on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator<=(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<LeExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies greater than on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator>(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<GtExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies greater than or equal on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator>=(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<GeExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies equals to on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator==(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<EqExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies not equals to on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator!=(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<NeqExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies plus on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator+(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();
	_expr = std::make_shared<PlusExpression>(std::move(_expr), other.get());
	setType( will_be_float ? Expression::Type::Float : Expression::Type::Int );
	return *this;
}

/**
 * Applies minus on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator-(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();
	_expr = std::make_shared<MinusExpression>(std::move(_expr), other.get());
	setType( will_be_float ? Expression::Type::Float : Expression::Type::Int );
	return *this;
}

/**
 * Applies multiplication on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator*(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();
	_expr = std::make_shared<MultiplyExpression>(std::move(_expr), other.get());
	setType( will_be_float ? Expression::Type::Float : Expression::Type::Int );
	return *this;
}

/**
 * Applies division on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator/(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();
	_expr = std::make_shared<DivideExpression>(std::move(_expr), other.get());
	setType( will_be_float ? Expression::Type::Float : Expression::Type::Int );
	return *this;
}

/**
 * Applies modulo on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator%(const YaraExpressionBuilder& other)
{
	bool will_be_float = _expr->isFloat() || other._expr->isFloat();
	_expr = std::make_shared<ModuloExpression>(std::move(_expr), other.get());
	setType( will_be_float ? Expression::Type::Float : Expression::Type::Int );
	return *this;
}

/**
 * Applies bitwise xor on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator^(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<BitwiseXorExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise and on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator&(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<BitwiseAndExpression>(std::move(_expr), other.get());

	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise or on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator|(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<BitwiseOrExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise shift left on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator<<(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<ShiftLeftExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Int);
	return *this;
}

/**
 * Applies bitwise shift right on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::operator>>(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<ShiftRightExpression>(std::move(_expr), other.get());
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
	std::vector<Expression::Ptr> exprArgs;
	std::for_each(args.begin(), args.end(), [&exprArgs](const YaraExpressionBuilder& expr) { exprArgs.push_back(expr.get()); });
	_expr = std::make_shared<FunctionCallExpression>(std::move(_expr), std::move(exprArgs));
	return *this;
}

/**
 * Applies operation contains on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::contains(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<ContainsExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Bool);
	return *this;
}

/**
 * Applies operation matches on two expression.
 *
 * @param other The other expression.
 *
 * @return Builder.
 */
YaraExpressionBuilder& YaraExpressionBuilder::matches(const YaraExpressionBuilder& other)
{
	_expr = std::make_shared<MatchesExpression>(std::move(_expr), other.get());
	setType(Expression::Type::Bool);
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
	auto symbol = std::make_shared<ValueSymbol>(attr, Expression::Type::Object);
	_expr = std::make_shared<StructAccessExpression>(symbol, std::move(_expr));
	setType(symbol->getDataType());
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
	_expr = std::make_shared<ArrayAccessExpression>(std::make_shared<ValueSymbol>("dummy", Expression::Type::Object), std::move(_expr), other.get());
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
	const std::string& function_name = endianness == IntFunctionEndianness::Big ? "int8be" : "int8";
	_expr = std::make_shared<IntFunctionExpression>(function_name, std::move(_expr));
	setType(Expression::Type::Int);
	return *this;
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
	const std::string& function_name = endianness == IntFunctionEndianness::Big ? "int16be" : "int16";
	_expr = std::make_shared<IntFunctionExpression>(function_name, std::move(_expr));
	setType(Expression::Type::Int);
	return *this;
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
	const std::string& function_name = endianness == IntFunctionEndianness::Big ? "int32be" : "int32";
	_expr = std::make_shared<IntFunctionExpression>(function_name, std::move(_expr));
	setType(Expression::Type::Int);
	return *this;
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
	const std::string& function_name = endianness == IntFunctionEndianness::Big ? "uint8be" : "uint8";
	_expr = std::make_shared<IntFunctionExpression>(function_name, std::move(_expr));
	setType(Expression::Type::Int);
	return *this;
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
	const std::string& function_name = endianness == IntFunctionEndianness::Big ? "uint16be" : "uint16";
	_expr = std::make_shared<IntFunctionExpression>(function_name, std::move(_expr));
	setType(Expression::Type::Int);
	return *this;
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
	const std::string& function_name = endianness == IntFunctionEndianness::Big ? "uint32be" : "uint32";
	_expr = std::make_shared<IntFunctionExpression>(function_name, std::move(_expr));
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
	return YaraExpressionBuilder(std::make_shared<IntLiteralExpression>(value, std::make_optional<std::string>(std::move(strValue))), Expression::Type::Int);
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
	return YaraExpressionBuilder(std::make_shared<IntLiteralExpression>(value, std::move(strValue)), Expression::Type::Int);
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
	return YaraExpressionBuilder(std::make_shared<IntLiteralExpression>(value, numToStr(value, std::hex, true)), Expression::Type::Int);
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
	return YaraExpressionBuilder(std::make_shared<DoubleLiteralExpression>(value, numToStr(value)), Expression::Type::Float);
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
	return YaraExpressionBuilder(std::make_shared<StringLiteralExpression>(value), Expression::Type::String);
}

/**
 * Creates the boolean expression.
 *
 * @param value Boolean value.
 *
 * @return Builder.
 */
YaraExpressionBuilder boolVal(bool value)
{
	return YaraExpressionBuilder(std::make_shared<BoolLiteralExpression>(value), Expression::Type::Bool);
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
	auto expression = std::make_shared<IdExpression>( std::make_shared<ValueSymbol>(id, Expression::Type::Object) );
	return YaraExpressionBuilder(expression);
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
	return YaraExpressionBuilder(std::make_shared<ParenthesesExpression>(other.get(), linebreak), other.getType());
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
	if (endsWith(id, '*'))
		return YaraExpressionBuilder(std::make_shared<StringWildcardExpression>(id));
	else
		return YaraExpressionBuilder(std::make_shared<StringExpression>(id), Expression::Type::Bool);
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

	return YaraExpressionBuilder(std::make_shared<StringCountExpression>(std::move(countId)), Expression::Type::Int);
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
	return YaraExpressionBuilder(std::make_shared<StringLengthExpression>(std::move(lengthId)), Expression::Type::Int);
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
	return YaraExpressionBuilder(std::make_shared<StringOffsetExpression>(std::move(offsetId)), Expression::Type::Int);
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
	return YaraExpressionBuilder(std::make_shared<StringLengthExpression>(std::move(lengthId), other.get()), Expression::Type::Int);
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
	return YaraExpressionBuilder(std::make_shared<StringOffsetExpression>(std::move(offsetId), other.get()), Expression::Type::Int);
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
	return YaraExpressionBuilder(std::make_shared<StringAtExpression>(id, other.get()), Expression::Type::Bool);
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
	return YaraExpressionBuilder(std::make_shared<StringInRangeExpression>(id, other.get()), Expression::Type::Bool);
}

/**
 * Creates the for loop expression over set of integers using iterating variable with given name.
 *
 * @param forExpr Expression specifying requirement of the for loop.
 * @param id Name of the iterating variable.
 * @param set Set of integers.
 * @param expr Body of the for loop.
 *
 * @return Builder.
 */
YaraExpressionBuilder forLoop(const YaraExpressionBuilder& forExpr, const std::string& id, const YaraExpressionBuilder& set, const YaraExpressionBuilder& expr)
{
	return YaraExpressionBuilder(std::make_shared<ForIntExpression>(forExpr.get(), id, set.get(), expr.get()), Expression::Type::Bool);
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
	return YaraExpressionBuilder(std::make_shared<ForStringExpression>(forExpr.get(), set.get(), expr.get()), Expression::Type::Bool);
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
	return YaraExpressionBuilder(std::make_shared<OfExpression>(ofExpr.get(), set.get()), Expression::Type::Bool);
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
	std::vector<Expression::Ptr> elementsExprs;
	std::for_each(elements.begin(), elements.end(), [&elementsExprs](const YaraExpressionBuilder& expr) { elementsExprs.push_back(expr.get()); });
	return YaraExpressionBuilder(std::make_shared<SetExpression>(std::move(elementsExprs)));
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
	if( !lhs.canBeBool() )
		error_handle(ArgType::Left, "and", "bool", rhs.get());
	else if( !rhs.canBeBool() )
		error_handle(ArgType::Right, "and", "bool", lhs.get());
	return YaraExpressionBuilder(std::make_shared<AndExpression>(lhs.get(), rhs.get(), linebreak), Expression::Type::Bool);
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
	if( !lhs.canBeBool() )
		error_handle(ArgType::Left, "or", "bool", lhs.get());
	else if( !rhs.canBeBool() )
		error_handle(ArgType::Right, "or", "bool", rhs.get());
	return YaraExpressionBuilder(std::make_shared<OrExpression>(lhs.get(), rhs.get(), linebreak), Expression::Type::Bool);
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
	for( const auto& bld : terms )
		if(!bld.canBeBool())
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
	for( const auto& bld : terms )
		if(!bld.canBeBool())
			error_handle(ArgType::Single, "or", "bool", bld.get());
	return logicalFormula(terms, [linebreaks](YaraExpressionBuilder& term1, YaraExpressionBuilder& term2) { return disjunction(term1, term2, linebreaks); });
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
	return YaraExpressionBuilder(std::make_shared<RangeExpression>(low.get(), high.get()));
}

/**
 * Creates the expression with keyword @c filesize.
 *
 * @return Builder.
 */
YaraExpressionBuilder filesize()
{
	return YaraExpressionBuilder(std::make_shared<FilesizeExpression>(), Expression::Type::Int);
}

/**
 * Creates the expression with keyword @c entrypoint.
 *
 * @return Builder.
 */
YaraExpressionBuilder entrypoint()
{
	return YaraExpressionBuilder(std::make_shared<EntrypointExpression>(), Expression::Type::Int);
}

/**
 * Creates the expression with keyword @c all.
 *
 * @return Builder.
 */
YaraExpressionBuilder all()
{
	return YaraExpressionBuilder(std::make_shared<AllExpression>());
}

/**
 * Creates the expression with keyword @c any.
 *
 * @return Builder.
 */
YaraExpressionBuilder any()
{
	return YaraExpressionBuilder(std::make_shared<AnyExpression>());
}

/**
 * Creates the expression with keyword @c them.
 *
 * @return Builder.
 */
YaraExpressionBuilder them()
{
	return YaraExpressionBuilder(std::make_shared<ThemExpression>());
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
	return YaraExpressionBuilder(ts, std::make_shared<RegexpExpression>(std::move(regexp)), Expression::Type::Regexp);
}

}
