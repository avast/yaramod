/**
 * @file src/types/expressions.h
 * @brief Declaration of all Expression subclasses.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once
#include <sstream>

#include "yaramod/types/expression.h"
#include "yaramod/types/string.h"
#include "yaramod/types/symbol.h"
#include "yaramod/utils/utils.h"
#include "yaramod/utils/visitor.h"

namespace yaramod {

/**
 * Class representing expression which references string defined
 * in the strings section of the YARA rule.
 *
 * For example:
 * @code
 * $str at entrypoint
 * ^^^^
 * @endcode
 */
class StringExpression : public Expression
{
public:
   StringExpression(const std::string& id) { _id = _tokenStream->emplace_back(STRING_ID, id); }
   StringExpression(std::string&& id) { _id = _tokenStream->emplace_back(STRING_ID, std::move(id)); }
   StringExpression(TokenIt id) : _id(id) {}

   virtual VisitResult accept(Visitor* v) override
   {
      return v->visit(this);
   }

   const std::string& getId() const { return _id->getString(); }

   void setId(const std::string& id) { _id->setValue(id); }
   void setId(std::string&& id) { _id->setValue(std::move(id)); }

   virtual std::string getText(const std::string& /*indent*/ = "") const override
   {
      return getId();
   }

private:
   TokenIt _id; ///< Identifier of the string, std::string
};

/**
 * Class representing expression which references string using wildcard.
 * This is usable only in string sets used in string-based for loops.
 *
 * For example:
 * @code
 * for any of ($a*) : ( $ at entrypoint )
 *             ^^^
 * @endcode
 */
class StringWildcardExpression : public Expression
{
public:
   template<typename Str>
   StringWildcardExpression(Str&& id)
   {
      _id = _tokenStream->emplace_back(STRING_ID, std::forward<Str>(id));
   }
   StringWildcardExpression(TokenIt it) : _id(it) {}

   virtual VisitResult accept(Visitor* v) override
   {
      return v->visit(this);
   }

   const std::string& getId() const { return _id->getString(); }

   void setId(const std::string& id) { _id->setValue(id); }
   void setId(std::string&& id) { _id->setValue(std::move(id)); }

   virtual std::string getText(const std::string& /*indent*/ = "") const override
   {
      return getId();
   }

private:
   TokenIt _id; ///< Wildcard identifier of the string
};

/**
 * Class representing expression which references string at certain integer offset.
 *
 * For example:
 * @code
 * $str at 0x100
 * @endcode
 */
class StringAtExpression : public Expression
{
public:
	template<typename ExpPtr>
	StringAtExpression(const std::string& id, ExpPtr&& at)
		: _at(std::forward<ExpPtr>(at))
	{
      _id = _tokenStream->emplace_back(STRING_ID, id);
      _at_symbol = _tokenStream->emplace_back(OP_AT, "at");
      _tokenStream->move_append(_at->getTokenStream());
	}

	template<typename ExpPtr>
	StringAtExpression(TokenIt id, TokenIt at_symbol, ExpPtr&& at)
		: _id(id)
		, _at_symbol(at_symbol)
		, _at(std::forward<ExpPtr>(at))
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id->getString(); }
	const Expression::Ptr& getAtExpression() const { return _at; }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }
	void setAtExpression(const Expression::Ptr& at) { _at = at; }
	void setAtExpression(Expression::Ptr&& at) { _at = std::move(at); }

	virtual std::string getText(const std::string& indent = "") const override
	{
		return getId() + " " + _at_symbol->getString() + " " + _at->getText(indent);
	}

private:
	TokenIt _id; ///< Identifier of the string
	TokenIt _at_symbol; ///< Token holding "at"
	Expression::Ptr _at; ///< Integer part of the expression
};

/**
 * Class representing expression which references string in certain integer range.
 *
 * For example:
 * @code
 * $str in (0x100 .. 0x200)
 * @endcode
 */
class StringInRangeExpression : public Expression
{
public:
	template<typename ExpPtr>
	StringInRangeExpression(const std::string& id, ExpPtr&& range)
	{
		_id = _tokenStream->emplace_back(STRING_ID, id);
		_in_symbol = _tokenStream->emplace_back(OP_IN, "in");
		_range = std::forward<ExpPtr>(range);
      _tokenStream->move_append(_range->getTokenStream());
	}

	template<typename ExpPtr>
	StringInRangeExpression(TokenIt id, TokenIt in_symbol, ExpPtr&& range)
		: _id(id)
		, _in_symbol(in_symbol)
		, _range(std::forward<ExpPtr>(range))
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id->getString(); }
	const Expression::Ptr& getRangeExpression() const { return _range; }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }
	void setRangeExpression(const Expression::Ptr& range) { _range = range; }
	void setRangeExpression(Expression::Ptr&& range) { _range = std::move(range); }

	virtual std::string getText(const std::string& indent = "") const override
	{
		return getId() + " " + _in_symbol->getString() + " " + _range->getText(indent);
	}

private:
	TokenIt _id; ///< Identifier of the string
	TokenIt _in_symbol; ///< Token holding "at"
	Expression::Ptr _range; ///< Range expression
};

/**
 * Class representing expression which references string match count.
 *
 * For example:
 * @code
 * #str > 1
 * ^^^^
 * @endcode
 */
class StringCountExpression : public Expression
{
public:
	StringCountExpression(TokenIt id) : _id(id) {}

	template<typename Str>
	StringCountExpression(Str&& id)
	{
		_id = _tokenStream->emplace_back(STRING_COUNT, std::forward<Str>(id));
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id->getString(); }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _id->getString();
	}

private:
	TokenIt _id; ///< Identifier of the string
};

/**
 * Class representing expression which references first string match offset
 * or specific Nth match offset.
 *
 * For example:
 * @code
 * (@str > 0x100) and (@str[2] < 0x1000)
 *  ^^^^               ^^^^^^^
 * @endcode
 */
class StringOffsetExpression : public Expression
{
public:
	StringOffsetExpression(TokenIt id)
		: _id(id)
	{
	}
	template<typename ExpPtr>
	StringOffsetExpression(TokenIt id, ExpPtr&& expr)
		: _id(id)
		, _expr(std::forward<ExpPtr>(expr))
	{
	}
	template<typename Str>
	StringOffsetExpression(Str&& id)
	{
		_id = _tokenStream->emplace_back(STRING_OFFSET, std::forward<Str>(id));
	}
	template<typename Str, typename ExpPtr>
	StringOffsetExpression(Str&& id, ExpPtr&& expr)
		: _expr(std::forward<ExpPtr>(expr))
	{
		_id = _tokenStream->emplace_back(STRING_OFFSET, std::forward<Str>(id));
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id->getString(); }
	const Expression::Ptr& getIndexExpression() const { return _expr; }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }
	void setIndexExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setIndexExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _expr ? getId() + '[' + _expr->getText(indent) + ']' : getId();
	}

private:
	TokenIt _id; ///< Identifier of the string
	Expression::Ptr _expr; ///< Index expression if any
};

/**
 * Class representing expression which references first string match length
 * or specific Nth match length.
 *
 * For example:
 * @code
 * (!str > 5) and (!str[2] < 10)
 *  ^^^^           ^^^^^^^
 * @endcode
 */
class StringLengthExpression : public Expression
{
public:
	StringLengthExpression(TokenIt id)
		: _id(id)
	{
	}
	template<typename ExpPtr>
	StringLengthExpression(TokenIt id, ExpPtr&& expr)
		: _id(id)
		, _expr(std::forward<ExpPtr>(expr))
	{
	}
	template<typename Str>
	StringLengthExpression(Str&& id)
	{
		_id = _tokenStream->emplace_back(STRING_LENGTH, std::forward<Str>(id));
	}
	template<typename Str, typename ExpPtr>
	StringLengthExpression(Str&& id, ExpPtr&& expr)
		: _expr(std::forward<ExpPtr>(expr))
	{
		_id = _tokenStream->emplace_back(STRING_LENGTH, std::forward<Str>(id));
	}
	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id->getString(); }
	const Expression::Ptr& getIndexExpression() const { return _expr; }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }
	void setIndexExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setIndexExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _expr ? getId() + '[' + _expr->getText(indent) + ']' : getId();
	}

private:
	TokenIt _id; ///< Identifier of the string
	Expression::Ptr _expr; ///< Index expression if any
};

/**
 * Abstract class representing some unary operation.
 */
class UnaryOpExpression : public Expression
{
public:
	virtual std::string getText(const std::string& indent = "") const override
	{
		if(_op->getType() == NOT)
			return _op->getString() + " " + _expr->getText(indent);
		else
			return _op->getString() + _expr->getText(indent);
	}

	const Expression::Ptr& getOperand() const { return _expr; }

	void setOperand(const Expression::Ptr& expr) { _expr = expr; }
	void setOperand(Expression::Ptr&& expr) { _expr = std::move(expr); }

protected:
	template<typename ExpPtr>
	UnaryOpExpression(TokenIt op, ExpPtr&& expr)
		: _op(op)
		, _expr(std::forward<ExpPtr>(expr))
	{
	}
	template<typename ExpPtr>
	UnaryOpExpression(const std::string& op, TokenType type, ExpPtr&& expr)
		: _expr(std::forward<ExpPtr>(expr))
	{
		_op = _tokenStream->emplace_back(type, op);
	}

private:
	TokenIt _op; ///< Unary operation symbol, std::string
	Expression::Ptr _expr; ///< Expression to apply operator on
};

/**
 * Class representing logical not operation.
 *
 * For example:
 * @code
 * !(@str > 10)
 * @endcode
 */
class NotExpression : public UnaryOpExpression //odpovida not v condition
{
public:
	template<typename ExpPtr>
	NotExpression(ExpPtr&& expr) : UnaryOpExpression("not", NOT, std::forward<ExpPtr>(expr)) {}
	template<typename ExpPtr>
	NotExpression(TokenIt op, ExpPtr&& expr) : UnaryOpExpression(op, std::forward<ExpPtr>(expr)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing unary minus operation.
 *
 * For example:
 * @code
 * @str1 - @str2 == -20
 *                  ^^^
 * @endcode
 */
class UnaryMinusExpression : public UnaryOpExpression
{
public:
	template<typename ExpPtr>
	UnaryMinusExpression(ExpPtr&& expr) : UnaryOpExpression("-", MINUS, std::forward<ExpPtr>(expr)) {}
	template<typename ExpPtr>
	UnaryMinusExpression(TokenIt op, ExpPtr&& expr) : UnaryOpExpression(op, std::forward<ExpPtr>(expr)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing bitwise not operation.
 *
 * For example:
 * @code
 * ~uint8(0x0) == 0xab
 * ^^^^^^^^^^^
 * @endcode
 */
class BitwiseNotExpression : public UnaryOpExpression
{
public:
	template<typename ExpPtr>
	BitwiseNotExpression(ExpPtr&& expr) : UnaryOpExpression("~", BITWISE_NOT, std::forward<ExpPtr>(expr)) {}
	template<typename ExpPtr>
	BitwiseNotExpression(TokenIt op, ExpPtr&& expr) : UnaryOpExpression(op, std::forward<ExpPtr>(expr)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Abstract class representing some binary operation.
 */
class BinaryOpExpression : public Expression
{
public:
	virtual std::string getText(const std::string& indent = "") const override
	{
		return _left->getText(indent) + ' ' + _op->getString() + (_linebreak ? "\n" + indent : " ") + _right->getText(indent);
	}

	const Expression::Ptr& getLeftOperand() const { return _left; }
	const Expression::Ptr& getRightOperand() const { return _right; }

	void setLeftOperand(Expression::Ptr&& left) { _left = std::move(left); }
	void setRightOperand(Expression::Ptr&& right) { _right = std::move(right); }
	void setLeftOperand(const Expression::Ptr& left) { _left = left; }
	void setRightOperand(const Expression::Ptr& right) { _right = right; }

protected:
	template<typename ExpPtr1, typename ExpPtr2>
	BinaryOpExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right, bool linebreak = false)
		: _op(op)
		, _left(std::forward<ExpPtr1>(left))
		, _right(std::forward<ExpPtr2>(right))
		, _linebreak(linebreak)
	{
	}
	template<typename ExpPtr1, typename ExpPtr2>
	BinaryOpExpression(ExpPtr1&& left, const std::string& op, TokenType type, ExpPtr2&& right, bool linebreak = false)
		: _left(std::forward<ExpPtr1>(left))
		, _right(std::forward<ExpPtr2>(right))
		, _linebreak(linebreak)
	{
		_op = _tokenStream->emplace_back(type, op);
	}

private:
	TokenIt _op; ///< Binary operation symbol, std::string
	Expression::Ptr _left, _right; ///< Expressions to apply operation on
	bool _linebreak; ///< Put linebreak after operation symbol
};

/**
 * Class representing logical and operation.
 *
 * For example:
 * @code
 * $str1 and $str2
 * @endcode
 */
class AndExpression : public BinaryOpExpression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	AndExpression(ExpPtr1&& left, TokenIt and_op, ExpPtr2&& right, bool linebreak = false) : BinaryOpExpression(std::forward<ExpPtr1>(left), and_op, std::forward<ExpPtr2>(right), linebreak) {}
	template<typename ExpPtr1, typename ExpPtr2>
	AndExpression(ExpPtr1&& left, ExpPtr2&& right, bool linebreak = false) : BinaryOpExpression(std::forward<ExpPtr1>(left), "and", AND, std::forward<ExpPtr2>(right), linebreak) {}


	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing logical or operation.
 *
 * For example:
 * @code
 * $str1 or $str2
 * @endcode
 */
class OrExpression : public BinaryOpExpression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	OrExpression(ExpPtr1&& left, ExpPtr2&& right, bool linebreak = false) : BinaryOpExpression( std::forward<ExpPtr1>(left), "or", OR, std::forward<ExpPtr2>(right), linebreak) {}
	template<typename ExpPtr1, typename ExpPtr2>
	OrExpression(ExpPtr1&& left, TokenIt op_or, ExpPtr2&& right, bool linebreak = false) : BinaryOpExpression( std::forward<ExpPtr1>(left), op_or, std::forward<ExpPtr2>(right), linebreak) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing less than operation.
 *
 * For example:
 * @code
 * @str1 < @str2
 * @endcode
 */
class LtExpression : public BinaryOpExpression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	LtExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "<", LT, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	LtExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing greater than operation.
 *
 * For example:
 * @code
 * @str1 > @str2
 * @endcode
 */
class GtExpression : public BinaryOpExpression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	GtExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), ">", GT, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	GtExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing less or equal than operation.
 *
 * For example:
 * @code
 * @str1 <= @str2
 * @endcode
 */
class LeExpression : public BinaryOpExpression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	LeExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "<=", LE, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	LeExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing greater or equal than operation.
 *
 * For example:
 * @code
 * @str1 >= @str2
 * @endcode
 */
class GeExpression : public BinaryOpExpression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	GeExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), ">=", GE, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	GeExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing is equal operation.
 *
 * For example:
 * @code
 * !str1 == !str2
 * @endcode
 */
class EqExpression : public BinaryOpExpression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	EqExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "==", EQ, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	EqExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing is not equal operation.
 *
 * For example:
 * @code
 * !str1 != !str2
 * @endcode
 */
class NeqExpression : public BinaryOpExpression
{
public:
	// NeqExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("!=", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	NeqExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "!=", NEQ, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	NeqExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing contains operation on two strings.
 *
 * For example:
 * @code
 * pe.sections[0] contains "text"
 * @endcode
 */
class ContainsExpression : public BinaryOpExpression
{
public:
	// ContainsExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("contains", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	ContainsExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "contains", CONTAINS, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	ContainsExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing contains operation on string and regular expression.
 *
 * For example:
 * @code
 * pe.sections[0] matches /(text|data)/
 * @endcode
 */
class MatchesExpression : public BinaryOpExpression
{
public:
	// MatchesExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("matches", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	MatchesExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "matches", MATCHES, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	MatchesExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing arithmetic plus operation.
 *
 * For example:
 * @code
 * @str1 + 0x100 == @str2
 * ^^^^^^^^^^^^^
 * @endcode
 */
class PlusExpression : public BinaryOpExpression
{
public:
	// PlusExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("+", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	PlusExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "+", PLUS, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	PlusExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing arithmetic minus operation.
 *
 * For example:
 * @code
 * @str1 - 0x100 == @str2
 * ^^^^^^^^^^^^^
 * @endcode
 */
class MinusExpression : public BinaryOpExpression
{
public:
	// MinusExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("-", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	MinusExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "-", MINUS, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	MinusExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing arithmetic multiply operation.
 *
 * For example:
 * @code
 * @str1 * 2 == @str2
 * ^^^^^^^^^
 * @endcode
 */
class MultiplyExpression : public BinaryOpExpression
{
public:
	// MultiplyExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("*", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	MultiplyExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "*", MULTIPLY, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	MultiplyExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing arithmetic division operation.
 *
 * For example:
 * @code
 * @str1 \ 2 == @str2
 * ^^^^^^^^^
 * @endcode
 */
class DivideExpression : public BinaryOpExpression
{
public:
	// DivideExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("\\", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	DivideExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "\\", DIVIDE, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	DivideExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing arithmetic integral modulo operation.
 *
 * For example:
 * @code
 * @str1 % 2 == 0
 * ^^^^^^^^^
 * @endcode
 */
class ModuloExpression : public BinaryOpExpression
{
public:
	// ModuloExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("%", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	ModuloExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "%", MODULO, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	ModuloExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing bitwise xor operation
 *
 * For example:
 * @code
 * uint8(0x10) ^ uint8(0x20) == 0
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 * @endcode
 */
class BitwiseXorExpression : public BinaryOpExpression
{
public:
	// BitwiseXorExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("^", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	BitwiseXorExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "^", BITWISE_XOR, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	BitwiseXorExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing bitwise and operation
 *
 * For example:
 * @code
 * pe.characteristics & pe.DLL
 * @endcode
 */
class BitwiseAndExpression : public BinaryOpExpression
{
public:
	// BitwiseAndExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("&", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	BitwiseAndExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "&", BITWISE_AND, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	BitwiseAndExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing bitwise and operation
 *
 * For example:
 * @code
 * pe.characteristics | pe.DLL
 * @endcode
 */
class BitwiseOrExpression : public BinaryOpExpression
{
public:
	// BitwiseOrExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("|", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	BitwiseOrExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "|", BITWISE_OR, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	BitwiseOrExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing bitwise shift left operation
 *
 * For example:
 * @code
 * uint8(0x10) << 2
 * @endcode
 */
class ShiftLeftExpression : public BinaryOpExpression
{
public:
	// ShiftLeftExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("<<", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	ShiftLeftExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), "<<", SHIFT_LEFT, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	ShiftLeftExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing bitwise shift left operation
 *
 * For example:
 * @code
 * uint8(0x10) >> 2
 * @endcode
 */
class ShiftRightExpression : public BinaryOpExpression
{
public:
	// ShiftRightExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression(">>", left, right) {}
	template<typename ExpPtr1, typename ExpPtr2>
	ShiftRightExpression(ExpPtr1&& left, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), ">>", SHIFT_RIGHT, std::forward<ExpPtr2>(right)) {}
	template<typename ExpPtr1, typename ExpPtr2>
	ShiftRightExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Abstract class representing for loop. For loop can be either
 * over integers or set of string references. They can be distinguished
 * by keywords 'in' and 'of'. Integer for loop uses 'in' and string for loop
 * uses 'of'. When iterating over set of integers, the symbol obtaining
 * values of these integer is defined together with for loop. String-based for loops
 * may also have string sets substituted with keyword 'them' to reference all strings
 * in the string section.
 */
class ForExpression : public Expression
{
public:
	const Expression::Ptr& getVariable() const { return _forExpr; }
	const Expression::Ptr& getIteratedSet() const { return _set; }
	const Expression::Ptr& getBody() const { return _expr; }

	void setVariable(const Expression::Ptr& forExpr) { _forExpr = forExpr; }
	void setVariable(Expression::Ptr&& forExpr) { _forExpr = std::move(forExpr); }
	void setIteratedSet(const Expression::Ptr& set) { _set = set; }
	void setIteratedSet(Expression::Ptr&& set) { _set = std::move(set); }
	void setBody(const Expression::Ptr& expr) { _expr = expr; }
	void setBody(Expression::Ptr&& expr) { _expr = std::move(expr); }

protected:
	template<typename ExpPtr1, typename ExpPtr2>
	ForExpression( ExpPtr1&& forExpr, ExpPtr2&& set )
		: _forExpr( std::forward<ExpPtr1>(forExpr) )
		, _set( std::forward<ExpPtr2>(set) )
		, _expr( nullptr )
	{
	}

	template<typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForExpression( ExpPtr1&& forExpr, ExpPtr2&& set, ExpPtr3&& expr )
		: _forExpr( std::forward<ExpPtr1>(forExpr) )
		, _set( std::forward<ExpPtr2>(set) )
		, _expr( std::forward<ExpPtr3>(expr) )
	{
	}

	template<typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForExpression(ExpPtr1&& forExpr, ExpPtr2&& set, ExpPtr3&& expr, TokenIt of_in)
		: _forExpr(std::forward<ExpPtr1>(forExpr))
		, _set(std::forward<ExpPtr2>(set))
		, _expr(std::forward<ExpPtr3>(expr))
		, _of_in(of_in)
	{
	}

	template<typename ExpPtr1, typename ExpPtr2>
	ForExpression(ExpPtr1&& forExpr, ExpPtr2&& set, TokenIt of_in)
		: _forExpr(std::forward<ExpPtr1>(forExpr))
		, _set(std::forward<ExpPtr2>(set))
		, _expr(nullptr)
		, _of_in(of_in)
	{
	}

	Expression::Ptr _forExpr, _set, _expr;
	TokenIt _of_in;
};

/**
 * Class representing for loop over integer set or integer range.
 *
 * For example:
 * @code
 * for all i in (1 .. 5) : ( #str[i] > 0 }
 * @endcode
 */
class ForIntExpression : public ForExpression
{
public:
	/**
	 * Constructor used by builder.Example:
	 * for all i in (1 .. 5) : ( #str[i] > 0 }
	 *
	 * @param Expression::Ptr forExpr     "all"
	 * @param std::string id               "i"
	 * @param Expression::Ptr set       "(1 .. 5)"
	 * @param Expression::Ptr expr     "#str[i] > 0"
	 */
	template<typename S, typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForIntExpression(ExpPtr1&& forExpr, S id, ExpPtr2&& set, ExpPtr3&& expr)
		: ForExpression(std::forward<ExpPtr1>(forExpr), std::forward<ExpPtr2>(set), std::forward<ExpPtr3>(expr))
	{
		_for = _tokenStream->emplace_back(FOR, "for");
		_tokenStream->move_append(_forExpr->getTokenStream());
		_id = _tokenStream->emplace_back(ID, std::forward<S>(id));
		_of_in = _tokenStream->emplace_back(IN, "in");
		_tokenStream->move_append(_set->getTokenStream());
		_left_bracket = _tokenStream->emplace_back(LP, "(");
		_tokenStream->move_append(_expr->getTokenStream());
		_right_bracket = _tokenStream->emplace_back(RP, ")");
	}
	/**
	 * Constructor used by parser. Example:
	 * for all i in (1 .. 5) : ( #str[i] > 0 }
	 *
	 * @param Expression::Ptr forExpr     "all"
	 * @param TokenIt id                   "i"
	 * @param Expression::Ptr set       "(1 .. 5)"
	 * @param Expression::Ptr expr     "#str[i] > 0"
	 * @param TokenIt in                   "in"
	 * @param TokenIt left_bracket          "("
	 * @param TokenIt right_bracket         ")"
	 */
	template<typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForIntExpression(ExpPtr1&& forExpr, TokenIt id, ExpPtr2&& set, ExpPtr3&& expr, TokenIt for_token, TokenIt in, TokenIt left_bracket, TokenIt right_bracket)
		: ForExpression(std::forward<ExpPtr1>(forExpr), std::forward<ExpPtr2>(set), std::forward<ExpPtr3>(expr), in)
		, _id(id)
		, _for(for_token)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		assert(_set);
		std::stringstream ss;
		ss << _for->getString() << " " << _forExpr->getText(indent) << " " << _id->getString() << " " << _of_in->getString() << " " << _set->getText(indent) << " : " << _left_bracket->getString() << " " << _expr->getText(indent) << " " << _right_bracket->getString();
		return ss.str();
	}

private:
	TokenIt _id; ///< Iterating identifier
	TokenIt _for;
	TokenIt _left_bracket;
	TokenIt _right_bracket;
};

/**
 * Class representing for loop over string set.
 *
 * For example:
 * @code
 * for all of ($str1, $str2) : ( $ at entrypoint )
 * @endcode
 */
class ForStringExpression : public ForExpression
{
public:
	/**
	 * Constructor for builder.
	 */
	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForStringExpression(ExpPtr1&& forExpr, ExpPtr2&& set, ExpPtr3&& expr)
		: ForExpression(std::forward<ExpPtr1>(forExpr), std::forward<ExpPtr2>(set), std::forward<ExpPtr3>(expr))
	{
		_for = _tokenStream->emplace_back(FOR, "for");
		_tokenStream->move_append(_forExpr->getTokenStream());
		_of_in = _tokenStream->emplace_back(OF, "of");
		_tokenStream->move_append(_set->getTokenStream());
		_left_bracket = _tokenStream->emplace_back(LP, "(");
		_tokenStream->move_append(_expr->getTokenStream());
		_right_bracket = _tokenStream->emplace_back(RP, ")");
	}

	/**
	 * Constructor for parser.
	 */
	template<typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForStringExpression(ExpPtr1&& forExpr, ExpPtr2&& set, ExpPtr3&& expr, TokenIt for_token, TokenIt of, TokenIt left_bracket, TokenIt right_bracket)
		: ForExpression(std::forward<ExpPtr1>(forExpr), std::forward<ExpPtr2>(set), std::forward<ExpPtr3>(expr), of)
		, _for(for_token)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _for->getString() + " " + _forExpr->getText(indent) + " " + _of_in->getString() + " " + _set->getText(indent) + " : " + _left_bracket->getString() + " " + _expr->getText(indent) + " " + _right_bracket->getString();
	}
private:
	TokenIt _for;
	TokenIt _left_bracket;
	TokenIt _right_bracket;
};

/**
 * Class representing 'of' expression. 'of' expression is shortened version of
 * for loop over string set with no loop body. It has hidden body which always contains just ( $ ).
 *
 * For example:
 * @code
 * all of ($str1, $str2)
 * @endcode
 */
class OfExpression : public ForExpression
{
public:
	/**
	 * Constructor for builder.
	 */
	template<typename ExpPtr1, typename ExpPtr2>
	OfExpression(ExpPtr1&& forExpr, ExpPtr2&& set)
		: ForExpression(std::forward<ExpPtr1>(forExpr), std::forward<ExpPtr2>(set))
	{
		_tokenStream->move_append(_forExpr->getTokenStream());
		_of_in = _tokenStream->emplace_back(OF, "of");
		_tokenStream->move_append(_set->getTokenStream());
	}
	/**
	 * Constructor for parser.
	 */
	template<typename ExpPtr1, typename ExpPtr2>
	OfExpression(ExpPtr1&& forExpr, ExpPtr2&& set, TokenIt of)
		: ForExpression(std::forward<ExpPtr1>(forExpr), std::forward<ExpPtr2>(set), of)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _forExpr->getText(indent) + " " + _of_in->getString() + " " + _set->getText(indent);
	}
};

/**
 * Class representing set of either strings or integers. String set may also contain
 * string wildcard referencing more than one string with single identifier.
 *
 * For example:
 * @code
 * for all i in (1,2,3,4,5) : ( $str at ( entrypoint + i ) )
 *              ^^^^^^^^^^^
 * all of ($str*,$1,$2)
 *        ^^^^^^^^^^^^^
 * @endcode
 */
class SetExpression : public Expression
{
public:
	template<typename ExpPtrVector>
	SetExpression(ExpPtrVector&& elements)
		: _elements(std::forward<ExpPtrVector>(elements))
	{
		_left_bracket = _tokenStream->emplace_back(LP, "(");
		for(size_t i = 0; i < _elements.size(); ++i )
		{
			_tokenStream->move_append(_elements[i]->getTokenStream());
			if(i < _elements.size() - 1)
				_tokenStream->emplace_back(COMMA, ",");
		}
		_right_bracket = _tokenStream->emplace_back(RP, ")");
	}
	template<typename ExpPtrVector>
	SetExpression(TokenIt left_bracket, ExpPtrVector&& elements, TokenIt right_bracket)
		: _left_bracket(left_bracket)
		, _elements(std::forward<ExpPtrVector>(elements))
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		std::ostringstream ss;
		ss << _left_bracket->getString();
		for (const auto& elem : _elements)
			ss << elem->getText(indent) << ", ";
		ss <<_right_bracket->getString();

		// Remove last ', ' from the result.
		auto text = ss.str();
		text.erase(text.length() - 3, 2);
		return text;
	}

	const std::vector<Expression::Ptr>& getElements() const { return _elements; }

	void setElements(const std::vector<Expression::Ptr>& elements)
	{
		_elements = elements;
	}

	void setElements(std::vector<Expression::Ptr>&& elements)
	{
		_elements = std::move(elements);
	}

private:
	TokenIt _left_bracket;
	std::vector<Expression::Ptr> _elements; ///< Elements of the set
	TokenIt _right_bracket;
};

/**
 * Class representing range of integers.
 *
 * For example:
 * @code
 * $str in (0x100 .. 0x200)
 *         ^^^^^^^^^^^^^^^^
 * @endcode
 */
class RangeExpression : public Expression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	RangeExpression(ExpPtr1&& low, ExpPtr2&& high)
		: _low(std::forward<ExpPtr1>(low))
		, _high(std::forward<ExpPtr2>(high))
	{
		_left_bracket = _tokenStream->emplace_back(LP, "(");
		_tokenStream->move_append(_low->getTokenStream());
		_double_dot = _tokenStream->emplace_back(DOUBLE_DOT, "..");
		_tokenStream->move_append(_high->getTokenStream());
		_right_bracket = _tokenStream->emplace_back(RP, ")");
	}

	template<typename ExpPtr1, typename ExpPtr2>
	RangeExpression(TokenIt left_bracket, ExpPtr1&& low, TokenIt double_dot, ExpPtr2&& high, TokenIt right_bracket)
		: _left_bracket(left_bracket)
		, _low(std::forward<ExpPtr1>(low))
		, _double_dot(double_dot)
		, _high(std::forward<ExpPtr2>(high))
		, _right_bracket(right_bracket)
	{
	}
	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _left_bracket->getString() + _low->getText(indent) + " " + _double_dot->getString() + " " + _high->getText(indent) + _right_bracket->getString();
	}

	const Expression::Ptr& getLow() const { return _low; }
	const Expression::Ptr& getHigh() const { return _high; }

	void setLow(const Expression::Ptr& low) { _low = low; }
	void setLow(Expression::Ptr&& low) { _low = std::move(low); }
	void setHigh(const Expression::Ptr& high) { _high = high; }
	void setHigh(Expression::Ptr&& high) { _high = std::move(high); }

private:
	TokenIt _left_bracket;
	Expression::Ptr _low;
	TokenIt _double_dot;
	Expression::Ptr _high; ///< Low and high bounds of the range
	TokenIt _right_bracket;
};

/**
 * Class representing identifier expression. This can be either identifier of the imported module,
 * identifier of the variable in the integer-based for loop or reference to another rule in the YARA file.
 *
 * For example:
 * @code
 * rule1 and pe.number_of_sections > 2
 * ^^^^^     ^^
 * @endcode
 */
class IdExpression : public Expression
{
public:
	IdExpression(const std::shared_ptr<Symbol>& symbol)
	{
		if(symbol)
			_symbol = _tokenStream->emplace_back(SYMBOL, symbol, symbol->getName());
	}

	IdExpression(TokenIt symbol)
		: _symbol(symbol)
	{
		assert(symbol->isSymbol());
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		if(_symbol)
			return _symbol.value()->getSymbol()->getName();
		return std::string();
	}

	const std::shared_ptr<Symbol>& getSymbol() const
	{
		assert(_symbol.has_value());
		return _symbol.value()->getSymbol();
	}

	void setSymbol(const std::shared_ptr<Symbol>& symbol)
	{
		assert(_symbol.has_value());
	 	_symbol.value()->setValue(symbol, symbol->getName());
	}

protected:
	std::optional<TokenIt> _symbol; ///< Symbol of the identifier
};

/**
 * Class representing access to the structure identifier. Structure identifier may only be imported module identifier,
 * or another attributes of the imported module structure.
 *
 * For example:
 * @code
 * pe.number_of_sections > 2
 * ^^^^^^^^^^^^^^^^^^^^^
 * @endcode
 */
class StructAccessExpression : public IdExpression
{
public:
	template<typename ExpPtr>
	StructAccessExpression(const std::shared_ptr<Symbol>& symbol, ExpPtr&& structure)
		: IdExpression(symbol)
		, _structure(std::forward<ExpPtr>(structure))
	{
		_dot = _tokenStream->emplace_back(DOT, ".");
		_tokenStream->move_append(_structure->getTokenStream());
	}
	template<typename ExpPtr>
	StructAccessExpression(TokenIt symbol, ExpPtr&& structure, TokenIt dot)
		: IdExpression(symbol)
		, _structure(std::forward<ExpPtr>(structure))
		, _dot(dot)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		if(_symbol)
			return _structure->getText(indent) + _dot->getString() + _symbol.value()->getSymbol()->getName();
		return _structure->getText(indent) + _dot->getString();
	}

	const Expression::Ptr& getStructure() const { return _structure; }

	void setStructure(const Expression::Ptr& structure) { _structure = structure; }
	void setStructure(Expression::Ptr&& structure) { _structure = std::move(structure); }

private:
	Expression::Ptr _structure; ///< Structure identifier expression
	TokenIt _dot; //'.'
};

/**
 * Class representing access to the array or the dictionary identifier. Array and dictionary identifiers may only be
 * attributes of the imported module structure.
 *
 * For example:
 * @code
 * pe.sections[0].name contains "text"
 *    ^^^^^^^^^^^
 * @endcode
 */
class ArrayAccessExpression : public IdExpression
{
public:
	template<typename ExpPtr1, typename ExpPtr2>
	ArrayAccessExpression(const std::shared_ptr<Symbol>& symbol, ExpPtr1&& array, ExpPtr2&& accessor)
		: IdExpression(symbol)
		, _array(std::forward<ExpPtr1>(array))
		, _accessor(std::forward<ExpPtr2>(accessor))
	{
		_tokenStream->emplace_back(DOT, ".");
		_tokenStream->move_append(_array->getTokenStream());
		_left_bracket = _tokenStream->emplace_back(LSQB, "[");
		_tokenStream->move_append(_accessor->getTokenStream());
		_right_bracket = _tokenStream->emplace_back(RSQB, "]");
	}
	template<typename ExpPtr1, typename ExpPtr2>
	ArrayAccessExpression(TokenIt symbol, ExpPtr1&& array, TokenIt left_bracket, ExpPtr2&& accessor, TokenIt right_bracket)
		: IdExpression(symbol)
		, _array(std::forward<ExpPtr1>(array))
		, _left_bracket(left_bracket)
		, _accessor(std::forward<ExpPtr2>(accessor))
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _array->getText(indent) + _left_bracket->getString() + _accessor->getText(indent) + _right_bracket->getString();
	}

	const Expression::Ptr& getArray() const { return _array; }
	const Expression::Ptr& getAccessor() const { return _accessor; }

	void setArray(const Expression::Ptr& array) { _array = array; }
	void setArray(Expression::Ptr&& array) { _array = std::move(array); }
	void setAccessor(const Expression::Ptr& accessor) { _accessor = accessor; }
	void setAccessor(Expression::Ptr&& accessor) { _accessor = std::move(accessor); }

private:
	Expression::Ptr _array; ///< Array identifier expression
	TokenIt _left_bracket; //'['
	Expression::Ptr _accessor; ///< Accessor expression (expression enclosed in [])
	TokenIt _right_bracket; //']'
};

/**
 * Class representing call to a function. Functions may only be attributes of the imported module structure.
 *
 * For example:
 * @code
 * pe.exports("ExitProcess")
 *    ^^^^^^^^^^^^^^^^^^^^^^
 * @endcode
 */
class FunctionCallExpression : public IdExpression
{
public:
	template<typename ExpPtr, typename ExpPtrVector>
	FunctionCallExpression(ExpPtr&& func, ExpPtrVector&& args)
		: IdExpression(nullptr)
		, _func(std::forward<ExpPtr>(func))
		, _args(std::forward<ExpPtrVector>(args))
	{
		_tokenStream->move_append(_func->getTokenStream());
		_left_bracket = _tokenStream->emplace_back(LP, "(");
		for(size_t i = 0; i < _args.size(); ++i)
		{
			assert(_args[i]);
			_tokenStream->move_append(_args[i]->getTokenStream());
			if(i < _args.size() - 1)
				_tokenStream->emplace_back(COMMA, ",");
		}
		_right_bracket = _tokenStream->emplace_back(RP, ")");
	}
	template<typename ExpPtr, typename ExpPtrVector>
	FunctionCallExpression(Expression::Ptr&& func, TokenIt left_bracket, std::vector<Expression::Ptr>&& args, TokenIt right_bracket)
		: IdExpression(nullptr)
		, _func(std::forward<ExpPtr>(func))
		, _left_bracket(left_bracket)
		, _args(std::forward<ExpPtrVector>(args))
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		// Use just empty parentheses for parameter-less function
		if (_args.empty())
			return _func->getText(indent) + _left_bracket->getString() + _right_bracket->getString();

		std::ostringstream ss;
		ss << _func->getText(indent) << _left_bracket->getString();
		for (const auto& arg : _args)
		{
			ss << arg->getText(indent) << ", ";
		}
		ss << _right_bracket->getString();

		// Remove last ', ' from the result.
		auto text = ss.str();
		text.erase(text.length() - 3, 2);
		return text;
	}

	const Expression::Ptr& getFunction() const { return _func; }
	const std::vector<Expression::Ptr>& getArguments() const { return _args; }

	void setFunction(const Expression::Ptr& func) { _func = func; }
	void setFunction(Expression::Ptr&& func) { _func = std::move(func); }
	void setArguments(const std::vector<Expression::Ptr>& args) { _args = args; }
	void setArguments(std::vector<Expression::Ptr>&& args) { _args = std::move(args); }

private:
	Expression::Ptr _func; ///< Function identifier expression
	TokenIt _left_bracket; //'('
	std::vector<Expression::Ptr> _args; ///< Arguments expressions
	TokenIt _right_bracket; //')'
};

/**
 * Abstract class representing literal value expression of certain type T. This class is intended to be
 * inherited as specialization.
 */
template <typename T>
class LiteralExpression : public Expression
{
public:
	using LiteralType = T;

	LiteralExpression() = default;
	LiteralExpression(TokenIt value) : _value(value) {}
	LiteralExpression(std::shared_ptr<TokenStream> ts, TokenIt value) //no need to have emplacing here - Builder takes care of that.
		: Expression(ts)
		, _value(value)
	{
	}
	// LiteralType getValue() const
	// {
	// 	assert(_value.has_value());
	// 	return T();
	// 	// return _value.value()->getValue<T>();
	// }

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		if(_value.has_value()){
			return _value.value()->getText();
		}
		else
			return std::string();
	}

	// virtual void clear() override
	void clear()
	{
		if(_value.has_value())
			_tokenStream->erase(_value.value());
	}

protected:
	std::optional<TokenIt> _value; ///< Value of the literal
};

/**
 * Class representing boolean literal expression. Can be either true or false.
 *
 * For example:
 * @code
 * true or false
 * ^^^^    ^^^^^
 * @endcode
 */
class BoolLiteralExpression : public LiteralExpression<bool>
{
public:
	BoolLiteralExpression(TokenIt value)
		: LiteralExpression<bool>(value)
	{
	}
	BoolLiteralExpression(bool value)
		: LiteralExpression<bool>()
	{
		if(value)
			_value = _tokenStream->emplace_back(BOOL_TRUE, value, "true");
		else
			_value = _tokenStream->emplace_back(BOOL_FALSE, value, "false");
	}
	BoolLiteralExpression(std::shared_ptr<TokenStream> ts, TokenIt value)
		: LiteralExpression<bool>(ts, value)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	bool getValue() const
	{
		assert(_value.has_value());
		return _value.value()->getBool();
	}
};

/**
 * Class representing string literal expression. Strings are enclosed in double quotes.
 *
 * For example:
 * @code
 * pe.section[0].name contains "text"
 *                             ^^^^^^
 * @endcode
 */
class StringLiteralExpression : public LiteralExpression<std::string>
{
public:
	StringLiteralExpression(TokenIt value)
		: LiteralExpression<std::string>(value)
	{
	}
	StringLiteralExpression(const std::string& value)
		: LiteralExpression<std::string>()
	{
		_value = _tokenStream->emplace_back(STRING_LITERAL, value);
	}
	StringLiteralExpression(std::string&& value)
		: LiteralExpression<std::string>()
	{
		_value = _tokenStream->emplace_back(STRING_LITERAL, std::move(value));
	}
	StringLiteralExpression(std::shared_ptr<TokenStream> ts, TokenIt value)
		: LiteralExpression<std::string>(ts, value)
	{
	}
	// StringLiteralExpression(std::string&& str) : LiteralExpression<std::string>(std::move(str)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	std::string getValue() const
	{
		assert(_value.has_value());
		return _value.value()->getString();
	}
};

/**
 * Class representing integer literal expression. Integers are stored in string representation to preserve
 * base and preceding zeroes.
 *
 * For example:
 * @code
 * @str1 == 0x100
 *          ^^^^^
 * @endcode
 */
class IntLiteralExpression : public LiteralExpression<uint64_t>
{
public:
	IntLiteralExpression(TokenIt value)
		: LiteralExpression<uint64_t>(value)
	{
	}
	IntLiteralExpression(std::shared_ptr<TokenStream> ts, TokenIt value)
		: LiteralExpression<uint64_t>(ts, value)
	{
	}
	IntLiteralExpression(uint64_t value, const std::optional<std::string>& formatted_value = std::nullopt)
		: LiteralExpression<uint64_t>()
	{
		_value = _tokenStream->emplace_back(INTEGER, value, formatted_value);
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	uint64_t getValue() const
	{
		assert(_value.has_value());
		return _value.value()->getUInt64_t();
	}
};

/**
 * Class representing floating point literal expression. Floats are stored in string representation to preserve
 * preceding and trailing zeroes.
 *
 * For example:
 * @code
 * math.mean(0, filesize) < 72.0
 *                          ^^^^
 * @endcode
 */
class DoubleLiteralExpression : public LiteralExpression<double>
{
public:
	DoubleLiteralExpression(TokenIt value) // parser uses this
		: LiteralExpression<double>(value)
	{
	}
	DoubleLiteralExpression(std::shared_ptr<TokenStream> ts, TokenIt value)
		: LiteralExpression<double>(ts, value)
	{
	}// DoubleLiteralExpression(std::string&& value) : LiteralExpression<std::string>(std::move(value)) {}
	DoubleLiteralExpression(double value, const std::optional<std::string>& formatted_value = std::nullopt) //builder uses this
		: LiteralExpression<double>()
	{
		_value = _tokenStream->emplace_back(DOUBLE, value, formatted_value);
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	double getValue() const
	{
		assert(_value.has_value());
		return _value.value()->getDouble();
	}
};

/**
 * Abstract class representing expression that is formed just of one keyword.
 */
class KeywordExpression : public Expression
{
public:
	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _keyword->getString();
	}

protected:
	KeywordExpression() = default;
	KeywordExpression(TokenIt keyword)
		: _keyword(keyword)
	{
		assert(keyword->isString());
	}
	// void setValue(TokenIt t)
	// {
	// 	_keyword = t;
	// }
	// KeywordExpression(std::shared_ptr<TokenStream> ts, TokenIt keyword)
	// 	: Expression(ts)
	// 	, _keyword(keyword)
	// {
	// 	assert(keyword->isString());
	// }
	TokenIt _keyword; ///< Keyword
};

/**
 * Class representing 'filesize' expression. This is integer expression.
 *
 * For example:
 * @code
 * uint32(@str1) < filesize
 *                 ^^^^^^^^
 * @endcode
 */
class FilesizeExpression : public KeywordExpression
{
public:
	FilesizeExpression()
	{
		_keyword = _tokenStream->emplace_back(FILESIZE, "filesize");
	}
	FilesizeExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing 'entrypoint' expression. This is integer expression.
 *
 * For example:
 * @code
 * $str1 at entrypoint
 *          ^^^^^^^^^^
 * @endcode
 */
class EntrypointExpression : public KeywordExpression
{
public:
	EntrypointExpression()
	{
		_keyword = _tokenStream->emplace_back(ENTRYPOINT, "entrypoint");
	}
	EntrypointExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing 'all' expression. Can be used in conjunction with for loops indicating that for loop
 * needs to be evaluated true for all variables in the referenced set. This expression does not have a type.
 *
 * For example:
 * @code
 * all of them
 * ^^^
 * @endcode
 */
class AllExpression : public KeywordExpression
{
public:
	AllExpression()
	{
		_keyword = _tokenStream->emplace_back(ALL, "all");
	}
	AllExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing 'any' expression. Can be used in conjunction with for loops indicating that for loop
 * needs to be evaluated true for at least one variables in the referenced set. This expression does not have a type.
 *
 * For example:
 * @code
 * any of them
 * ^^^
 * @endcode
 */
class AnyExpression : public KeywordExpression
{
public:
	AnyExpression()
	{
		_keyword = _tokenStream->emplace_back(ANY, "any");
	}
	AnyExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing 'them' expression. Can be used in conjunction with string-based for loops referencing
 * all string from the strings section instead of specific set. This expression does not have a type.
 *
 * For example:
 * @code
 * any of them
 *        ^^^^
 * @endcode
 */
class ThemExpression : public KeywordExpression
{
public:
	ThemExpression()
	{
		_keyword = _tokenStream->emplace_back(THEM, "them");
	}
	ThemExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}
};

/**
 * Class representing expression enclosed in parentheses. We need this kind of expression to preserve
 * parentheses when obtaining string representation of YARA file.
 *
 * For example:
 * @code
 * ((5 + 6) * 30) < filesize
 * ^^^^^^^^^^^^^^
 * @endcode
 */
class ParenthesesExpression : public Expression
{
public:
	/**
	 * Constructor used by builder.
	 *
	 * @param Expression::Ptr expr  argument inside the brackets.
	 * @param bool linebreak.
	 */
	template<typename ExpPtr>
	ParenthesesExpression(ExpPtr&& expr, bool linebreak = false)
		: _expr(std::forward<ExpPtr>(expr))
		, _linebreak(linebreak) //used only by builder, the expr->tokenStream must be extracted
	{
		_left_bracket = _tokenStream->emplace_back(LP, "(");
		_tokenStream->move_append(_expr->getTokenStream());
		_right_bracket = _tokenStream->emplace_back(RP, ")");
	}
	/**
	 * Constructor used by parser.
	 *
	 * @param TokenIt left_bracket.
	 * @param Expression::Ptr expr  argument inside the brackets.
	 * @param TokenIt right_bracket.
	 * @param bool linebreak.
	 */
	template<typename ExpPtr>
	ParenthesesExpression(TokenIt left_bracket, ExpPtr&& expr, TokenIt right_bracket) //linebreak uses only builder
		: _expr(std::forward<ExpPtr>(expr))
		, _linebreak(false)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		if (_linebreak)
		{
			auto newIndent = indent + '\t';
			return _left_bracket->getString() + '\n' + newIndent + _expr->getText(newIndent) + '\n' + indent + _right_bracket->getString();
		}

		return _left_bracket->getString() + _expr->getText(indent) + _right_bracket->getString();
	}

	const Expression::Ptr& getEnclosedExpression() const { return _expr; }

	void setEnclosedExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setEnclosedExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

private:
	Expression::Ptr _expr; ///< Enclosed expression
	bool _linebreak; ///< Put linebreak after opening and before closing parenthesis and indent content by one more level.
	TokenIt _left_bracket;
	TokenIt _right_bracket;
};

/**
 * Class representing call to special built-in functions for reading fixed-width integer values from the file.
 * These functions are @c int8, @c int16, @c int32 and their unsigned counterparts prefixed with @c u. These functions also
 * have big-endian version suffixed with @c be.
 *
 * For example:
 * @code
 * uint16(0) == 0x5A4D
 * ^^^^^^^^^
 * @endcode
 */
class IntFunctionExpression : public Expression
{
public:
	/**
	 * Constructor used by builder.
	 *
	 * @param std::string func  name of the function.
	 * @param Expression::Ptr expr  argument of the function.
	 */
	template<typename S, typename ExpPtr>
	IntFunctionExpression(S&& func, ExpPtr&& expr)
		: _expr(std::forward<ExpPtr>(expr))
	{
		_func = _tokenStream->emplace_back(INTEGER_FUNCTION, std::forward<S>(func));
		_left_bracket = _tokenStream->emplace_back(LP, "(");
		_tokenStream->move_append(_expr->getTokenStream());
		_right_bracket = _tokenStream->emplace_back(RP, ")");
	}
	/**
	 * Constructor used by parser.
	 *
	 * @param TokenIt func  name of the function.
	 * @param TokenIt left_bracket.
	 * @param Expression::Ptr expr  argument of the function.
	 * @param TokenIt right_bracket.
	 */
	template<typename ExpPtr>
	IntFunctionExpression(TokenIt func, TokenIt left_bracket, ExpPtr&& expr, TokenIt right_bracket)
		: _func(func)
		, _expr(std::forward<ExpPtr>(expr))
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _func->getString() + _left_bracket->getString() + _expr->getText(indent) + _right_bracket->getString();
	}

	const std::string& getFunction() const { return _func->getString(); }
	const Expression::Ptr& getArgument() const { return _expr; }

	void setFunction(const std::string& func) { _func->setValue(func); }
	void setFunction(std::string&& func) { _func->setValue(std::move(func)); }
	void setArgument(const Expression::Ptr& expr) { _expr = expr; }
	void setArgument(Expression::Ptr&& expr) { _expr = std::move(expr); }

private:
	TokenIt _func; ///< Function identifier
	Expression::Ptr _expr; ///< Function argument
	TokenIt _left_bracket;
	TokenIt _right_bracket;
};

/**
 * Class representing regular expression.
 *
 * For example:
 * @code
 * pe.sections[0].name matches /(text|data)/
 *                             ^^^^^^^^^^^^^
 * @endcode
 */
class RegexpExpression : public Expression
{
public:
	/**
	 * Constructor.
	 *
	 * @param std::string regexp.
	 */
	template<typename S>
	RegexpExpression(S&& regexp)
		: _regexp(std::forward<S>(regexp))
	{
		_tokenStream = _regexp->getTokenStream();
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = "") const override { return _regexp->getText(); }

	const std::shared_ptr<String>& getRegexpString() const { return _regexp; }

	void setRegexpString(const std::shared_ptr<String>& regexp) { _regexp = regexp; }
	void setRegexpString(std::shared_ptr<String>&& regexp) { _regexp = std::move(regexp); }

private:
	std::shared_ptr<String> _regexp; ///< Regular expression string
};

}
