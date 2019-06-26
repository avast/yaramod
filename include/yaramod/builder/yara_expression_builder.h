/**
 * @file src/builder/yara_expression_builder.h
 * @brief Declaration of class YaraExpressionBuilder.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>
#include <string>

#include "yaramod/types/expression.h"
#include "yaramod/types/symbol.h"
#include "yaramod/yaramod_error.h"

namespace yaramod {

/**
 * Enum representing KB and MB integer modifiers.
 */
enum class IntMultiplier
{
	None,
	Kilobytes,
	Megabytes
};

/**
 * Enum representing endianness of integer functions like
 * `int16`, `int16be` etc.
 */
enum class IntFunctionEndianness
{
	Little,
	Big
};

/**
 * Represents error during parsing.
 */
class YaraExpressionBuilderError : public YaramodError{
public:
	YaraExpressionBuilderError(const std::string& errorMsg)
		: YaramodError(std::string("YaraExpressionBuilder error: ") + errorMsg)
	{
	}
	YaraExpressionBuilderError(const YaraExpressionBuilderError&) = default;
};

/**
 * Class representing builder of condition expression. You use this builder
 * to specify what you want in your condition expression and then you can obtain
 * your condition expression by calling method @c get. As soon as @c get is called,
 * builder resets to default state and does not contain any data from
 * the previous build process. This builder modifies itself during the construction,
 * so if you want to hold the state of builder for later use you should first copy it.
 */
class YaraExpressionBuilder
{
public:
	/// @name Constructors
	/// @{
	YaraExpressionBuilder();
	YaraExpressionBuilder(const Expression::Ptr& expr);
	YaraExpressionBuilder(Expression::Ptr&& expr);
	YaraExpressionBuilder(const Expression::Ptr& expr, const Expression::Type& type);
	YaraExpressionBuilder(Expression::Ptr&& expr, const Expression::Type& type);
	YaraExpressionBuilder(const YaraExpressionBuilder&) = default;
	YaraExpressionBuilder(YaraExpressionBuilder&&) = default;
	/// @}

	/// @name Assignments
	/// @{
	YaraExpressionBuilder& operator=(const YaraExpressionBuilder&) = default;
	YaraExpressionBuilder& operator=(YaraExpressionBuilder&&) = default;
	/// @}

	/// @name Getter methods
	/// @{
	Expression::Type getType() const { return _expr->getType(); }
	/// @}

	/// @name Setter methods
	/// @{
	void setType(Expression::Type type) { _expr->setType(type); }
	/// @}

	/// @name Detection methods
	/// @{
	bool canBeBool() const
	{
		return _expr->isBool() || _expr->isFloat() || _expr->isInt() || _expr->isUndefined();
	}
	bool canBeNumber() const
	{
		return _expr->isInt() || _expr->isFloat() || _expr->isUndefined();
	}
	/// @}

	/// @name Builder method
	/// @{
	Expression::Ptr get() const;
	/// @}

	/// @name Building methods
	/// @{
	YaraExpressionBuilder& operator!();
	YaraExpressionBuilder& operator~();
	YaraExpressionBuilder& operator-();

	YaraExpressionBuilder& operator&&(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator||(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator<(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator<=(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator>(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator>=(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator==(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator!=(const YaraExpressionBuilder& other);

	YaraExpressionBuilder& operator+(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator-(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator*(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator/(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator%(const YaraExpressionBuilder& other);

	YaraExpressionBuilder& operator^(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator&(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator|(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator<<(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& operator>>(const YaraExpressionBuilder& other);

	YaraExpressionBuilder& call(const std::vector<YaraExpressionBuilder>& args);
	/**
	 * Calls function from an expression
	 *
	 * @param args Arguments of the function.
	 *
	 * @return Builder.
	 */
	template <typename... Args> YaraExpressionBuilder& operator()(const Args&... args)
	{
		std::vector<YaraExpressionBuilder> realArgs;
		_buildArgs(realArgs, args...);
		call(realArgs);
		return *this;
	}

	YaraExpressionBuilder& contains(const YaraExpressionBuilder& other);
	YaraExpressionBuilder& matches(const YaraExpressionBuilder& other);

	YaraExpressionBuilder& access(const std::string& attr);
	YaraExpressionBuilder& operator[](const YaraExpressionBuilder& other);

	YaraExpressionBuilder& readInt8(IntFunctionEndianness endianness);
	YaraExpressionBuilder& readInt16(IntFunctionEndianness endianness);
	YaraExpressionBuilder& readInt32(IntFunctionEndianness endianness);
	YaraExpressionBuilder& readUInt8(IntFunctionEndianness endianness);
	YaraExpressionBuilder& readUInt16(IntFunctionEndianness endianness);
	YaraExpressionBuilder& readUInt32(IntFunctionEndianness endianness);
	/// @}

protected:
	void _buildArgs(std::vector<YaraExpressionBuilder>&) {}

	void _buildArgs(std::vector<YaraExpressionBuilder>& realArgs, const YaraExpressionBuilder& arg)
	{
		realArgs.push_back(arg);
	}

	template <typename... Args> void _buildArgs(std::vector<YaraExpressionBuilder>& realArgs, const YaraExpressionBuilder& arg, const Args&... args)
	{
		realArgs.push_back(arg);
		_call(realArgs, args...);
	}

private:
	enum class OpType {Left, Right, Single};
	void error_handle(OpType operator_type, const std::string& op, const std::string& expected_type, const std::string& actual_value) const
	{
		if(operator_type == OpType::Single)
			throw YaraExpressionBuilderError("Invalid operand '" + actual_value + "'' for " + op + " operator. Expected " + expected_type + ".");
		else if(operator_type == OpType::Right)
			throw YaraExpressionBuilderError("Invalid right operand '" + actual_value + "'' for " + op + " operator. Expected " + expected_type + ".");
		else
			throw YaraExpressionBuilderError("Invalid left operand '" + actual_value + "'' for " + op + " operator. Expected " + expected_type + ".");
	}

	void error_handle(const std::string& msg) const
	{
		throw YaraExpressionBuilderError(msg);
	}

	Expression::Ptr _expr;
};

/// @name Helper functions
/// These functions serve for readable and easy way to construct
/// condition expressions using @c YaraExpressionBuilder.
/// @{
YaraExpressionBuilder intVal(std::int64_t value, IntMultiplier mult = IntMultiplier::None);
YaraExpressionBuilder uintVal(std::uint64_t value, IntMultiplier mult = IntMultiplier::None);
YaraExpressionBuilder hexIntVal(std::uint64_t value);
YaraExpressionBuilder doubleVal(double value);
YaraExpressionBuilder stringVal(const std::string& value);
YaraExpressionBuilder boolVal(bool value);

YaraExpressionBuilder id(const std::string& id);
YaraExpressionBuilder paren(const YaraExpressionBuilder& other, bool linebreak = false);

YaraExpressionBuilder stringRef(const std::string& id);
YaraExpressionBuilder matchCount(const std::string& id);
YaraExpressionBuilder matchLength(const std::string& id);
YaraExpressionBuilder matchOffset(const std::string& id);
YaraExpressionBuilder matchLength(const std::string& id, const YaraExpressionBuilder& other);
YaraExpressionBuilder matchOffset(const std::string& id, const YaraExpressionBuilder& other);
YaraExpressionBuilder matchAt(const std::string& id, const YaraExpressionBuilder& other);
YaraExpressionBuilder matchInRange(const std::string& id, const YaraExpressionBuilder& other);

YaraExpressionBuilder forLoop(const YaraExpressionBuilder& forExpr, const std::string& id, const YaraExpressionBuilder& set, const YaraExpressionBuilder& expr);
YaraExpressionBuilder forLoop(const YaraExpressionBuilder& forExpr, const YaraExpressionBuilder& set, const YaraExpressionBuilder& expr);
YaraExpressionBuilder of(const YaraExpressionBuilder& ofExpr, const YaraExpressionBuilder& set);

YaraExpressionBuilder set(const std::vector<YaraExpressionBuilder>& elements);
YaraExpressionBuilder range(const YaraExpressionBuilder& low, const YaraExpressionBuilder& high);

YaraExpressionBuilder conjunction(const YaraExpressionBuilder& lhs, const YaraExpressionBuilder& rhs, bool linebreak = false);
YaraExpressionBuilder disjunction(const YaraExpressionBuilder& lhs, const YaraExpressionBuilder& rhs, bool linebreak = false);
YaraExpressionBuilder conjunction(const std::vector<YaraExpressionBuilder>& terms, bool linebreaks = false);
YaraExpressionBuilder disjunction(const std::vector<YaraExpressionBuilder>& terms, bool linebreaks = false);

YaraExpressionBuilder filesize();
YaraExpressionBuilder entrypoint();
YaraExpressionBuilder all();
YaraExpressionBuilder any();
YaraExpressionBuilder them();

YaraExpressionBuilder regexp(const std::string& text, const std::string& suffixMods = "");
/// @}

}
