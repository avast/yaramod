/**
 * @file src/types/expression.h
 * @brief Declaration of class Expression.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "yaramod/utils/visitor_result.h"
#include "yaramod/types/token_stream.h"
#include "yaramod/types/expression_type.h"

namespace yaramod {

class Visitor;
class ModifyingVisitor;

/**
 * Class representing expression in the condition section
 * of the YARA rule. Expression bears the value of certain type.
 */
class Expression
{
public:
	using Ptr = std::shared_ptr<Expression>;

	///< Type of the expression.
	using Type = ExpressionType;

	/// @name Constructors
	/// @{
	Expression()
		: _tokenStream(std::make_shared<TokenStream>())
		, _type(Expression::Type::Undefined)
	{
	}
	Expression(const std::shared_ptr<TokenStream>& ts)
		: _tokenStream(ts)
		, _type(Expression::Type::Undefined)
	{
		assert(_tokenStream);
	}
	Expression(Expression&&) = default;
	virtual ~Expression() = default;
	/// @}

	/// @name Virtual methods
	/// @{
	virtual VisitResult acceptModifyingVisitor(ModifyingVisitor* v) = 0;
	virtual VisitResult accept(Visitor* v) = 0;
	virtual std::string getText(const std::string& indent = std::string{}) const = 0;
	/// @}

	/// @name Getter methods
	/// @{
	Expression::Type getType() const { return _type; }
	std::string getTypeString() const
	{
		switch(_type)
		{
			case Expression::Type::Bool: return "bool";
			case Expression::Type::Int: return "int";
			case Expression::Type::String: return "string";
			case Expression::Type::Regexp: return "regexp";
			case Expression::Type::Object: return "object";
			case Expression::Type::Float: return "float";
			case Expression::Type::Undefined: return "undefined";
			default: return "Error - unknown type";
		}
	}
	TokenStream* getTokenStream() const
	{
		return _tokenStream.get();
	}
	virtual TokenIt getFirstTokenIt() const = 0;
	virtual TokenIt getLastTokenIt() const = 0;
	/// @}
	

	/// @name Setter methods
	/// @{
	void setType(Expression::Type type) { _type = type; }
	void setTokenStream(const std::shared_ptr<TokenStream>& ts) { _tokenStream = ts; }
	/// @}

	/// @name Detection methods
	/// @{
	bool isBool() const { return _type == Expression::Type::Bool; }
	bool isInt() const { return _type == Expression::Type::Int; }
	bool isString() const { return _type == Expression::Type::String; }
	bool isRegexp() const { return _type == Expression::Type::Regexp; }
	bool isObject() const { return _type == Expression::Type::Object; }
	bool isFloat() const { return _type == Expression::Type::Float; }
	bool isUndefined() const { return _type == Expression::Type::Undefined; }
	/// @}

	/// @name Caster method
	/// @{
	template <typename T>
	T* as() noexcept { return dynamic_cast<T*>(this); }

	template <typename T>
	const T* as() const noexcept { return dynamic_cast<const T*>(this); }
	/// @}

protected:
	std::shared_ptr<TokenStream> _tokenStream;
	void extractTokens(const VisitResult& result, TokenIt from, TokenIt to)
	{
		std::shared_ptr<Expression> result_exp;
		try
		{
			result_exp = std::get<std::shared_ptr<Expression>>(result);
		}
		catch (std::bad_variant_access& err)
		{
			throw VisitorResultAccessError(err.what());
		}
		TokenIt firstNew = result_exp->getFirstTokenIt();
		TokenIt lastNew = std::next(result_exp->getLastTokenIt());
		if (getTokenStream() != result_exp->getTokenStream())
		{
			TokenIt before = _tokenStream->erase(from, to);
			_tokenStream->move_append(before, result_exp->getTokenStream(), firstNew, lastNew);
		}
		else
			std::cout << "Instead of replacing the expression the visitor only modified it. Chances are, the TokenStream was not modified appropriately." << std::endl;
		result_exp->setTokenStream(_tokenStream);
	}

private:
	Type _type; ///< Type of the expression
};

}
