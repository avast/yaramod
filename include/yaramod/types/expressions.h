/**
 * @file src/types/expressions.h
 * @brief Declaration of all Expression subclasses.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

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
	StringExpression(const std::string& id) : _id(id) {}
	StringExpression(std::string&& id) : _id(std::move(id)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id; }

	void setId(const std::string& id) { _id = id; }
	void setId(std::string&& id) { _id = std::move(id); }

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _id;
	}

private:
	std::string _id; ///< Identifier of the string
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
	StringWildcardExpression(const std::string& id) : _id(id) {}
	StringWildcardExpression(std::string&& id) : _id(std::move(id)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id; }

	void setId(const std::string& id) { _id = id; }
	void setId(std::string&& id) { _id = std::move(id); }

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _id;
	}

private:
	std::string _id; ///< Wildcard identifier of the string
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
	StringAtExpression(const std::string& id, const Expression::Ptr& at) : _id(id), _at(at) {}
	StringAtExpression(std::string&& id, Expression::Ptr&& at) : _id(std::move(id)), _at(std::move(at)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id; }
	const Expression::Ptr& getAtExpression() const { return _at; }

	void setId(const std::string& id) { _id = id; }
	void setId(std::string&& id) { _id = std::move(id); }
	void setAtExpression(const Expression::Ptr& at) { _at = at; }
	void setAtExpression(Expression::Ptr&& at) { _at = std::move(at); }

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _id + " at " + _at->getText(indent);
	}

private:
	std::string _id; ///< Identifier of the string
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
	StringInRangeExpression(const std::string& id, const Expression::Ptr& range) : _id(id), _range(range) {}
	StringInRangeExpression(std::string&& id, Expression::Ptr&& range) : _id(std::move(id)), _range(std::move(range)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id; }
	const Expression::Ptr& getRangeExpression() const { return _range; }

	void setId(const std::string& id) { _id = id; }
	void setId(std::string&& id) { _id = std::move(id); }
	void setRangeExpression(const Expression::Ptr& range) { _range = range; }
	void setRangeExpression(Expression::Ptr&& range) { _range = std::move(range); }

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _id + " in " + _range->getText(indent);
	}

private:
	std::string _id; ///< Identifier of the string
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
	StringCountExpression(const std::string& id) : _id(id) {}
	StringCountExpression(std::string&& id) : _id(std::move(id)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id; }

	void setId(const std::string& id) { _id = id; }
	void setId(std::string&& id) { _id = std::move(id); }

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _id;
	}

private:
	std::string _id; ///< Identifier of the string
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
	StringOffsetExpression(const std::string& id) : _id(id), _expr() {}
	StringOffsetExpression(std::string&& id) : _id(std::move(id)), _expr() {}
	StringOffsetExpression(const std::string& id, const Expression::Ptr& expr) : _id(id), _expr(expr) {}
	StringOffsetExpression(std::string&& id, const Expression::Ptr& expr) : _id(std::move(id)), _expr(expr) {}
	StringOffsetExpression(const std::string& id, Expression::Ptr&& expr) : _id(id), _expr(std::move(expr)) {}
	StringOffsetExpression(std::string&& id, Expression::Ptr&& expr) : _id(std::move(id)), _expr(std::move(expr)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id; }
	const Expression::Ptr& getIndexExpression() const { return _expr; }

	void setId(const std::string& id) { _id = id; }
	void setId(std::string&& id) { _id = std::move(id); }
	void setIndexExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setIndexExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _expr ? _id + '[' + _expr->getText(indent) + ']' : _id;
	}

private:
	std::string _id; ///< Identifier of the string
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
	StringLengthExpression(const std::string& id) : _id(id), _expr() {}
	StringLengthExpression(std::string&& id) : _id(std::move(id)), _expr() {}
	StringLengthExpression(const std::string& id, const Expression::Ptr& expr) : _id(id), _expr(expr) {}
	StringLengthExpression(std::string&& id, const Expression::Ptr& expr) : _id(std::move(id)), _expr(expr) {}
	StringLengthExpression(const std::string& id, Expression::Ptr&& expr) : _id(id), _expr(std::move(expr)) {}
	StringLengthExpression(std::string&& id, Expression::Ptr&& expr) : _id(std::move(id)), _expr(std::move(expr)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id; }
	const Expression::Ptr& getIndexExpression() const { return _expr; }

	void setId(const std::string& id) { _id = id; }
	void setId(std::string&& id) { _id = std::move(id); }
	void setIndexExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setIndexExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _expr ? _id + '[' + _expr->getText(indent) + ']' : _id;
	}

private:
	std::string _id; ///< Identifier of the string
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
		return _op + _expr->getText(indent);
	}

	const Expression::Ptr& getOperand() const { return _expr; }

	void setOperand(const Expression::Ptr& expr) { _expr = expr; }
	void setOperand(Expression::Ptr&& expr) { _expr = std::move(expr); }

protected:
	UnaryOpExpression(const std::string& op, const Expression::Ptr& expr)
		: _op(op), _expr(std::move(expr)) {}
	UnaryOpExpression(const std::string& op, Expression::Ptr&& expr)
		: _op(op), _expr(std::move(expr)) {}

private:
	std::string _op; ///< Unary operation symbol
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
class NotExpression : public UnaryOpExpression
{
public:
	NotExpression(const Expression::Ptr& expr) : UnaryOpExpression("not ", expr) {}
	NotExpression(Expression::Ptr&& expr) : UnaryOpExpression("not ", std::move(expr)) {}

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
	UnaryMinusExpression(const Expression::Ptr& expr) : UnaryOpExpression("-", expr) {}
	UnaryMinusExpression(Expression::Ptr&& expr) : UnaryOpExpression("-", std::move(expr)) {}

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
	BitwiseNotExpression(const Expression::Ptr& expr) : UnaryOpExpression("~", expr) {}
	BitwiseNotExpression(Expression::Ptr&& expr) : UnaryOpExpression("~", std::move(expr)) {}

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
		return _left->getText(indent) + ' ' + _op + (_linebreak ? "\n" + indent : " ") + _right->getText(indent);
	}

	const Expression::Ptr& getLeftOperand() const { return _left; }
	const Expression::Ptr& getRightOperand() const { return _right; }

	void setLeftOperand(const Expression::Ptr& left) { _left = left; }
	void setLeftOperand(Expression::Ptr&& left) { _left = std::move(left); }
	void setRightOperand(const Expression::Ptr& right) { _right = right; }
	void setRightOperand(Expression::Ptr&& right) { _right = std::move(right); }

protected:
	BinaryOpExpression(const std::string& op, const Expression::Ptr& left, const Expression::Ptr& right, bool linebreak = false)
		: _op(op), _left(std::move(left)), _right(std::move(right)), _linebreak(linebreak) {}
	BinaryOpExpression(const std::string& op, Expression::Ptr&& left, Expression::Ptr&& right, bool linebreak = false)
		: _op(op), _left(std::move(left)), _right(std::move(right)), _linebreak(linebreak) {}

private:
	std::string _op; ///< Binary operation symbol
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
	AndExpression(const Expression::Ptr& left, const Expression::Ptr& right, bool linebreak = false) : BinaryOpExpression("and", left, right, linebreak) {}
	AndExpression(Expression::Ptr&& left, Expression::Ptr&& right, bool linebreak = false) : BinaryOpExpression("and", std::move(left), std::move(right), linebreak) {}

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
	OrExpression(const Expression::Ptr& left, const Expression::Ptr& right, bool linebreak = false) : BinaryOpExpression("or", left, right, linebreak) {}
	OrExpression(Expression::Ptr&& left, Expression::Ptr&& right, bool linebreak = false) : BinaryOpExpression("or", std::move(left), std::move(right), linebreak) {}

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
	LtExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("<", left, right) {}
	LtExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("<", std::move(left), std::move(right)) {}

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
	GtExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression(">", left, right) {}
	GtExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression(">", std::move(left), std::move(right)) {}

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
	LeExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("<=", left, right) {}
	LeExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("<=", std::move(left), std::move(right)) {}

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
	GeExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression(">=", left, right) {}
	GeExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression(">=", std::move(left), std::move(right)) {}

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
	EqExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("==", left, right) {}
	EqExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("==", std::move(left), std::move(right)) {}

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
	NeqExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("!=", left, right) {}
	NeqExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("!=", std::move(left), std::move(right)) {}

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
	ContainsExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("contains", left, right) {}
	ContainsExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("contains", std::move(left), std::move(right)) {}

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
	MatchesExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("matches", left, right) {}
	MatchesExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("matches", std::move(left), std::move(right)) {}

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
	PlusExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("+", left, right) {}
	PlusExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("+", std::move(left), std::move(right)) {}

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
	MinusExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("-", left, right) {}
	MinusExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("-", std::move(left), std::move(right)) {}

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
	MultiplyExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("*", left, right) {}
	MultiplyExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("*", std::move(left), std::move(right)) {}

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
	DivideExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("\\", left, right) {}
	DivideExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("\\", std::move(left), std::move(right)) {}

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
	ModuloExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("%", left, right) {}
	ModuloExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("%", std::move(left), std::move(right)) {}

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
	BitwiseXorExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("^", left, right) {}
	BitwiseXorExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("^", std::move(left), std::move(right)) {}

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
	BitwiseAndExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("&", left, right) {}
	BitwiseAndExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("&", std::move(left), std::move(right)) {}

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
	BitwiseOrExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("|", left, right) {}
	BitwiseOrExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("|", std::move(left), std::move(right)) {}

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
	ShiftLeftExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression("<<", left, right) {}
	ShiftLeftExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression("<<", std::move(left), std::move(right)) {}

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
	ShiftRightExpression(const Expression::Ptr& left, const Expression::Ptr& right) : BinaryOpExpression(">>", left, right) {}
	ShiftRightExpression(Expression::Ptr&& left, Expression::Ptr&& right) : BinaryOpExpression(">>", std::move(left), std::move(right)) {}

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
	ForExpression(const Expression::Ptr& forExpr, const Expression::Ptr& set, const Expression::Ptr& expr)
		: _forExpr(forExpr), _set(set), _expr(expr) {}
	ForExpression(Expression::Ptr&& forExpr, Expression::Ptr&& set, Expression::Ptr&& expr)
		: _forExpr(std::move(forExpr)), _set(std::move(set)), _expr(std::move(expr)) {}

	Expression::Ptr _forExpr, _set, _expr;
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
	ForIntExpression(const Expression::Ptr& forExpr, const std::string& id, const Expression::Ptr& set, const Expression::Ptr& expr)
		: ForExpression(forExpr, set, expr), _id(id) {}
	ForIntExpression(Expression::Ptr&& forExpr, std::string&& id, Expression::Ptr&& set, Expression::Ptr&& expr)
		: ForExpression(std::move(forExpr), std::move(set), std::move(expr)), _id(std::move(id)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return "for " + _forExpr->getText(indent) + ' ' + _id + " in " + _set->getText(indent) + " : ( " + _expr->getText(indent) + " )";
	}

private:
	std::string _id; ///< Iterating identifier
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
	ForStringExpression(const Expression::Ptr& forExpr, const Expression::Ptr& set, const Expression::Ptr& expr)
		: ForExpression(forExpr, set, expr) {}
	ForStringExpression(Expression::Ptr&& forExpr, Expression::Ptr&& set, Expression::Ptr&& expr)
		: ForExpression(std::move(forExpr), std::move(set), std::move(expr)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return "for " + _forExpr->getText(indent) + " of " + _set->getText(indent) + " : ( " + _expr->getText(indent) + " )";
	}
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
	OfExpression(const Expression::Ptr& forExpr, const Expression::Ptr& set)
		: ForExpression(forExpr, set, nullptr) {}
	OfExpression(Expression::Ptr&& forExpr, Expression::Ptr&& set)
		: ForExpression(std::move(forExpr), std::move(set), nullptr) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _forExpr->getText(indent) + " of " + _set->getText(indent);
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
	SetExpression(const std::vector<Expression::Ptr>& elements) : _elements(elements) {}
	SetExpression(std::vector<Expression::Ptr>&& elements) : _elements(std::move(elements)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		std::ostringstream ss;
		ss << '(';
		for (const auto& elem : _elements)
		{
			ss << elem->getText(indent) << ", ";
		}
		ss << ')';

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
	std::vector<Expression::Ptr> _elements; ///< Elements of the set
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
	RangeExpression(const Expression::Ptr& low, const Expression::Ptr& high) : _low(low), _high(high) {}
	RangeExpression(Expression::Ptr&& low, Expression::Ptr&& high) : _low(std::move(low)), _high(std::move(high)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return '(' + _low->getText(indent) + " .. " + _high->getText(indent) + ')';
	}

	const Expression::Ptr& getLow() const { return _low; }
	const Expression::Ptr& getHigh() const { return _high; }

	void setLow(const Expression::Ptr& low) { _low = low; }
	void setLow(Expression::Ptr&& low) { _low = std::move(low); }
	void setHigh(const Expression::Ptr& high) { _high = high; }
	void setHigh(Expression::Ptr&& high) { _high = std::move(high); }

private:
	Expression::Ptr _low, _high; ///< Low and high bounds of the range
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
	IdExpression(const std::shared_ptr<Symbol>& symbol) : _symbol(symbol) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _symbol->getName();
	}

	const std::shared_ptr<Symbol>& getSymbol() const { return _symbol; }

	void setSymbol(const std::shared_ptr<Symbol>& symbol) { _symbol = symbol; }

protected:
	std::shared_ptr<Symbol> _symbol; ///< Symbol of the identifier
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
	StructAccessExpression(const std::shared_ptr<Symbol>& symbol, const Expression::Ptr& structure) : IdExpression(symbol), _structure(structure) {}
	StructAccessExpression(const std::shared_ptr<Symbol>& symbol, Expression::Ptr&& structure) : IdExpression(symbol), _structure(std::move(structure)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _structure->getText(indent) + '.' + _symbol->getName();
	}

	const Expression::Ptr& getStructure() const { return _structure; }

	void setStructure(const Expression::Ptr& structure) { _structure = structure; }
	void setStructure(Expression::Ptr&& structure) { _structure = std::move(structure); }

private:
	Expression::Ptr _structure; ///< Structure identifier expression
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
	ArrayAccessExpression(const std::shared_ptr<Symbol>& symbol, const Expression::Ptr& array, const Expression::Ptr& accessor)
		: IdExpression(symbol), _array(std::move(array)), _accessor(std::move(accessor)) {}
	ArrayAccessExpression(const std::shared_ptr<Symbol>& symbol, Expression::Ptr&& array, Expression::Ptr&& accessor)
		: IdExpression(symbol), _array(std::move(array)), _accessor(std::move(accessor)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _array->getText(indent) + '[' + _accessor->getText(indent) + ']';
	}

	const Expression::Ptr& getArray() const { return _array; }
	const Expression::Ptr& getAccessor() const { return _accessor; }

	void setArray(const Expression::Ptr& array) { _array = array; }
	void setArray(Expression::Ptr&& array) { _array = std::move(array); }
	void setAccessor(const Expression::Ptr& accessor) { _accessor = accessor; }
	void setAccessor(Expression::Ptr&& accessor) { _accessor = std::move(accessor); }

private:
	Expression::Ptr _array; ///< Array identifier expression
	Expression::Ptr _accessor; ///< Accessor expression (expression enclosed in [])
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
	FunctionCallExpression(const Expression::Ptr& func, const std::vector<Expression::Ptr>& args)
		: IdExpression(nullptr), _func(func), _args(args) {}
	FunctionCallExpression(Expression::Ptr&& func, std::vector<Expression::Ptr>&& args)
		: IdExpression(nullptr), _func(std::move(func)), _args(std::move(args)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		// Use just empty parentheses for parameter-less function
		if (_args.empty())
			return _func->getText(indent) + "()";

		std::ostringstream ss;
		ss << _func->getText(indent) << '(';
		for (const auto& arg : _args)
		{
			ss << arg->getText(indent) << ", ";
		}
		ss << ')';

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
	std::vector<Expression::Ptr> _args; ///< Arguments expressions
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

	LiteralExpression(const T& value) : _value(value) {}
	LiteralExpression(T&& value) : _value(std::move(value)) {}

	LiteralType getValue() const { return _value; }

protected:
	LiteralType _value; ///< Value of the literal
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
	BoolLiteralExpression(bool value) : LiteralExpression<bool>(value) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _value ? "true" : "false";
		//return _value;
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
	StringLiteralExpression(const std::string& str) : LiteralExpression<std::string>(str) {}
	StringLiteralExpression(std::string&& str) : LiteralExpression<std::string>(std::move(str)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return '"' + escapeString(_value) + '"';
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
class IntLiteralExpression : public LiteralExpression<std::string>
{
public:
	IntLiteralExpression(const std::string& value) : LiteralExpression<std::string>(value) {}
	IntLiteralExpression(std::string&& value) : LiteralExpression<std::string>(std::move(value)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _value;
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
class DoubleLiteralExpression : public LiteralExpression<std::string>
{
public:
	DoubleLiteralExpression(const std::string& value) : LiteralExpression<std::string>(value) {}
	DoubleLiteralExpression(std::string&& value) : LiteralExpression<std::string>(std::move(value)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = "") const override
	{
		return _value;
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
		return _keyword;
	}

protected:
	KeywordExpression(const std::string& keyword) : _keyword(keyword) {}
	KeywordExpression(std::string&& keyword) : _keyword(std::move(keyword)) {}

private:
	std::string _keyword; ///< Keyword
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
	FilesizeExpression() : KeywordExpression("filesize") {}

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
	EntrypointExpression() : KeywordExpression("entrypoint") {}

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
	AllExpression() : KeywordExpression("all") {}

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
	AnyExpression() : KeywordExpression("any") {}

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
	ThemExpression() : KeywordExpression("them") {}

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
	ParenthesesExpression(const Expression::Ptr& expr, bool linebreak = false) : _expr(expr), _linebreak(linebreak) {}
	ParenthesesExpression(Expression::Ptr&& expr, bool linebreak = false) : _expr(std::move(expr)), _linebreak(linebreak) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		if (_linebreak)
		{
			auto newIndent = indent + '\t';
			return "(\n" + newIndent + _expr->getText(newIndent) + '\n' + indent + ')';
		}

		return '(' + _expr->getText(indent) + ')';
	}

	const Expression::Ptr& getEnclosedExpression() const { return _expr; }

	void setEnclosedExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setEnclosedExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

private:
	Expression::Ptr _expr; ///< Enclosed expression
	bool _linebreak; ///< Put linebreak after opening and before closing parenthesis and indent content by one more level.
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
	IntFunctionExpression(const std::string& func, const Expression::Ptr& expr) : _func(func), _expr(expr) {}
	IntFunctionExpression(std::string&& func, Expression::Ptr&& expr) : _func(std::move(func)), _expr(std::move(expr)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = "") const override
	{
		return _func + '(' + _expr->getText(indent) + ')';
	}

	const std::string& getFunction() const { return _func; }
	const Expression::Ptr& getArgument() const { return _expr; }

	void setFunction(const std::string& func) { _func = func; }
	void setFunction(std::string&& func) { _func = std::move(func); }
	void setArgument(const Expression::Ptr& expr) { _expr = expr; }
	void setArgument(Expression::Ptr&& expr) { _expr = std::move(expr); }

private:
	std::string _func; ///< Function identifier
	Expression::Ptr _expr; ///< Function argument
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
	RegexpExpression(const std::shared_ptr<String>& regexp) : _regexp(regexp) {}
	RegexpExpression(std::shared_ptr<String>&& regexp) : _regexp(std::move(regexp)) {}

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
