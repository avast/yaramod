/**
 * @file src/types/expressions.h
 * @brief Declaration of all Expression subclasses.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once
#include <sstream>

#include "yaramod/types/expression.h"
#include "yaramod/types/regexp.h"
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
	StringExpression(const std::string& id) { _id = _tokenStream->emplace_back(TokenType::STRING_ID, id); }
	StringExpression(std::string&& id) { _id = _tokenStream->emplace_back(TokenType::STRING_ID, std::move(id)); }
	StringExpression(TokenIt id) : _id(id) {}
	StringExpression(const std::shared_ptr<TokenStream>& ts, TokenIt id) : Expression(ts), _id(id) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	std::string getId() const { return _id->getPureText(); }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }

	virtual TokenIt getFirstTokenIt() const override { return _id; }
	virtual TokenIt getLastTokenIt() const override { return _id; }

	virtual std::string getText(const std::string& /*indent*/ = std::string{}) const override
	{
		return getId();
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _id);
		auto newId = _id->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id), std::next(getLastTokenIt()));
		return std::make_shared<StringExpression>(target, newId);
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
	template <typename Str>
	StringWildcardExpression(Str&& id)
	{
		_id = _tokenStream->emplace_back(TokenType::STRING_ID, std::forward<Str>(id));
	}
	StringWildcardExpression(TokenIt it) : _id(it) {}
	StringWildcardExpression(const std::shared_ptr<TokenStream>& ts, TokenIt it) : Expression(ts), _id(it) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	const std::string& getId() const { return _id->getString(); }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }

	virtual TokenIt getFirstTokenIt() const override { return _id; }
	virtual TokenIt getLastTokenIt() const override { return _id; }

	virtual std::string getText(const std::string& /*indent*/ = std::string{}) const override
	{
		return getId();
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _id);
		auto newId = _id->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id), std::next(getLastTokenIt()));
		return std::make_shared<StringWildcardExpression>(target, newId);
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
	template <typename ExpPtr>
	StringAtExpression(const std::string& id, ExpPtr&& at)
		: _at(std::forward<ExpPtr>(at))
	{
		_id = _tokenStream->emplace_back(TokenType::STRING_ID, id);
		_at_symbol = _tokenStream->emplace_back(TokenType::OP_AT, "at");
		_tokenStream->moveAppend(_at->getTokenStream());
	}

	template <typename ExpPtr>
	StringAtExpression(TokenIt id, TokenIt at_symbol, ExpPtr&& at)
		: _id(id)
		, _at_symbol(at_symbol)
		, _at(std::forward<ExpPtr>(at))
	{
	}

	template <typename ExpPtr>
	StringAtExpression(const std::shared_ptr<TokenStream>& ts, TokenIt id, TokenIt at_symbol, ExpPtr&& at)
		: Expression(ts)
		, _id(id)
		, _at_symbol(at_symbol)
		, _at(std::forward<ExpPtr>(at))
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	std::string getId() const { return _id->getPureText(); }
	const Expression::Ptr& getAtExpression() const { return _at; }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }
	void setAtExpression(const Expression::Ptr& at) { _at = at; }
	void setAtExpression(Expression::Ptr&& at) { _at = std::move(at); }

	virtual TokenIt getFirstTokenIt() const override { return _id; }
	virtual TokenIt getLastTokenIt() const override { return _at->getLastTokenIt(); }

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		return getId() + " " + _at_symbol->getString() + " " + _at->getText(indent);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _id);
		auto newId = _id->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id), _at_symbol);
		auto newAtSymbol = _at_symbol->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_at_symbol), _at->getFirstTokenIt());
		auto newAt = _at->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_at->getLastTokenIt()), std::next(getLastTokenIt()));
		return std::make_shared<StringAtExpression>(target, newId, newAtSymbol, std::move(newAt));
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
	template <typename ExpPtr>
	StringInRangeExpression(const std::string& id, ExpPtr&& range)
	{
		_id = _tokenStream->emplace_back(TokenType::STRING_ID, id);
		_in_symbol = _tokenStream->emplace_back(TokenType::OP_IN, "in");
		_range = std::forward<ExpPtr>(range);
		_tokenStream->moveAppend(_range->getTokenStream());
	}

	template <typename ExpPtr>
	StringInRangeExpression(TokenIt id, TokenIt in_symbol, ExpPtr&& range)
		: _id(id)
		, _in_symbol(in_symbol)
		, _range(std::forward<ExpPtr>(range))
	{
	}

	template <typename ExpPtr>
	StringInRangeExpression(const std::shared_ptr<TokenStream>& ts, TokenIt id, TokenIt in_symbol, ExpPtr&& range)
		: Expression(ts)
		, _id(id)
		, _in_symbol(in_symbol)
		, _range(std::forward<ExpPtr>(range))
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	std::string getId() const { return _id->getPureText(); }
	const Expression::Ptr& getRangeExpression() const { return _range; }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }
	void setRangeExpression(const Expression::Ptr& range) { _range = range; }
	void setRangeExpression(Expression::Ptr&& range) { _range = std::move(range); }

	virtual TokenIt getFirstTokenIt() const override { return _id; }
	virtual TokenIt getLastTokenIt() const override { return _range->getLastTokenIt(); }

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		return getId() + " " + _in_symbol->getString() + " " + _range->getText(indent);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _id);
		auto newId = _id->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id), _in_symbol);
		auto newIn = _in_symbol->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_in_symbol), _range->getFirstTokenIt());
		auto newRange = _range->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_range->getLastTokenIt()), std::next(getLastTokenIt()));
		return std::make_shared<StringInRangeExpression>(target, newId, newIn, std::move(newRange));
	}

private:
	TokenIt _id; ///< Identifier of the string
	TokenIt _in_symbol; ///< Token holding "in"
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
	StringCountExpression(const std::shared_ptr<TokenStream>& ts, TokenIt id) : Expression(ts), _id(id) {}

	template <typename Str>
	StringCountExpression(Str&& id)
	{
		_id = _tokenStream->emplace_back(TokenType::STRING_COUNT, std::forward<Str>(id));
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	std::string getId() const { return _id->getPureText(); }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }

	virtual TokenIt getFirstTokenIt() const override { return _id; }
	virtual TokenIt getLastTokenIt() const override { return _id; }

	virtual std::string getText(const std::string& /*indent*/ = std::string{}) const override
	{
		auto output = getId();
		assert(output != std::string() && "String id must be non-empty.");
		output[0] = '#';
		return output;
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _id);
		auto newId = _id->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id), std::next(getLastTokenIt()));
		return std::make_shared<StringCountExpression>(target, newId);
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
		, _right_bracket()
	{
	}
	template <typename ExpPtr>
	StringOffsetExpression(TokenIt id, ExpPtr&& expr, TokenIt right_bracket)
		: _id(id)
		, _expr(std::forward<ExpPtr>(expr))
		, _right_bracket(right_bracket)
	{
	}
	template <typename Str>
	StringOffsetExpression(Str&& id)
	{
		_id = _tokenStream->emplace_back(TokenType::STRING_OFFSET, std::forward<Str>(id));
		_right_bracket.reset();
	}
	template <typename Str, typename ExpPtr>
	StringOffsetExpression(Str&& id, ExpPtr&& expr, TokenIt right_bracket)
		: _expr(std::forward<ExpPtr>(expr))
		, _right_bracket(right_bracket)
	{
		_id = _tokenStream->emplace_back(TokenType::STRING_OFFSET, std::forward<Str>(id));
	}
	template <typename ExpPtr>
	StringOffsetExpression(const std::shared_ptr<TokenStream>& ts, TokenIt id, ExpPtr&& expr, const std::optional<TokenIt>& right_bracket)
		: Expression(ts)
		, _id(id)
		, _expr(std::forward<ExpPtr>(expr))
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	std::string getId() const { return _id->getPureText(); }
	const Expression::Ptr& getIndexExpression() const { return _expr; }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }
	void setIndexExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setIndexExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		auto prefix = getId();
		assert(prefix != std::string() && "String id must be non-empty.");
		prefix[0] = '@';
		return _expr ? prefix + '[' + _expr->getText(indent) + ']' : prefix;
	}

	virtual TokenIt getFirstTokenIt() const override { return _id; }
	virtual TokenIt getLastTokenIt() const override { return _expr && _right_bracket.has_value() ? _right_bracket.value() : _id; }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		Expression::Ptr newExpr;
		std::optional<TokenIt> newRb;

		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _id);
		auto newId = _id->clone(target.get());
		if (_expr && _right_bracket.has_value())
		{
			auto rb = _right_bracket.value();
			target->cloneAppend(getTokenStream(), std::next(_id), _expr->getFirstTokenIt());
			newExpr = _expr->clone(target);
			target->cloneAppend(getTokenStream(), std::next(_expr->getLastTokenIt()), rb);
			newRb = rb->clone(target.get());
			target->cloneAppend(getTokenStream(), std::next(rb), std::next(getLastTokenIt()));
		}
		else
		{
			target->cloneAppend(getTokenStream(), std::next(_id), std::next(getLastTokenIt()));
		}
		return std::make_shared<StringOffsetExpression>(target, newId, std::move(newExpr), newRb);
	}

private:
	TokenIt _id; ///< Identifier of the string
	Expression::Ptr _expr; ///< Index expression if any
	std::optional<TokenIt> _right_bracket; ///< Right bracket of index expression (if any)
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
		, _right_bracket()
	{
	}
	template <typename ExpPtr>
	StringLengthExpression(TokenIt id, ExpPtr&& expr, TokenIt right_bracket)
		: _id(id)
		, _expr(std::forward<ExpPtr>(expr))
		, _right_bracket(right_bracket)
	{
	}
	template <typename Str>
	StringLengthExpression(Str&& id)
	{
		_id = _tokenStream->emplace_back(TokenType::STRING_LENGTH, std::forward<Str>(id));
		_right_bracket.reset();
	}
	template <typename Str, typename ExpPtr>
	StringLengthExpression(Str&& id, ExpPtr&& expr, TokenIt right_bracket)
		: _expr(std::forward<ExpPtr>(expr))
		, _right_bracket(right_bracket)
	{
		_id = _tokenStream->emplace_back(TokenType::STRING_LENGTH, std::forward<Str>(id));
		_tokenStream->moveAppend(_expr->getTokenStream());
	}
	template <typename ExpPtr>
	StringLengthExpression(const std::shared_ptr<TokenStream>& ts, TokenIt id, ExpPtr&& expr, const std::optional<TokenIt>& right_bracket)
		: Expression(ts)
		, _id(id)
		, _expr(std::forward<ExpPtr>(expr))
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	std::string getId() const { return _id->getPureText(); }
	const Expression::Ptr& getIndexExpression() const { return _expr; }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }
	void setIndexExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setIndexExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual TokenIt getFirstTokenIt() const override { return _id; }
	virtual TokenIt getLastTokenIt() const override { return _expr && _right_bracket.has_value() ? _right_bracket.value() : _id; }

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		auto prefix = getId();
		assert(prefix != std::string() && "String id must be non-empty.");
		prefix[0] = '!';
		return _expr ? getId() + '[' + _expr->getText(indent) + ']' : getId();
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		Expression::Ptr newExpr;
		std::optional<TokenIt> newRb;

		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _id);
		auto newId = _id->clone(target.get());
		if (_expr)
		{
			auto rb = _right_bracket.value();
			target->cloneAppend(getTokenStream(), std::next(_id), _expr->getFirstTokenIt());
			newExpr = _expr->clone(target);
			target->cloneAppend(getTokenStream(), std::next(_expr->getLastTokenIt()), rb);
			newRb = rb->clone(target.get());
			target->cloneAppend(getTokenStream(), std::next(rb), std::next(getLastTokenIt()));
		}
		else
		{
			target->cloneAppend(getTokenStream(), std::next(_id), std::next(getLastTokenIt()));
		}
		return std::make_shared<StringLengthExpression>(target, newId, std::move(newExpr), newRb);
	}

private:
	TokenIt _id; ///< Identifier of the string
	Expression::Ptr _expr; ///< Index expression if any
	std::optional<TokenIt> _right_bracket; ///< Right bracket of index expression (if any)
};

enum class UnaryOperatorPlacement
{
    Left,
    Right
};

/**
 * Abstract class representing some unary operation.
 */
class UnaryOpExpression : public Expression
{
public:
	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		if (_op->getType() == TokenType::NOT || _op->getType() == TokenType::DEFINED)
		{
			assert(_operatorPlacement == UnaryOperatorPlacement::Left);
			return _op->getString() + " " + _expr->getText(indent);
		}
		else
		{
			if (_operatorPlacement == UnaryOperatorPlacement::Left)
				return _op->getString() + _expr->getText(indent);
			else
				return _expr->getText(indent) + _op->getString();
		}
	}

	TokenIt getOperator() const { return _op; }
	const Expression::Ptr& getOperand() const { return _expr; }

	void setOperand(const Expression::Ptr& expr) { _expr = expr; }
	void setOperand(Expression::Ptr&& expr) { _expr = std::move(expr); }

protected:
	template <typename ExpPtr>
	UnaryOpExpression(TokenIt op, ExpPtr&& expr, UnaryOperatorPlacement operatorPlacement)
		: _op(op)
		, _expr(std::forward<ExpPtr>(expr))
		, _operatorPlacement(operatorPlacement)
	{
	}

	template <typename ExpPtr>
	UnaryOpExpression(const std::string& op, TokenType type, ExpPtr&& expr, UnaryOperatorPlacement operatorPlacement)
		: _expr(std::forward<ExpPtr>(expr))
		, _operatorPlacement(operatorPlacement)
	{
		_op = _tokenStream->emplace_back(type, op);
	}

	template <typename ExpPtr>
	UnaryOpExpression(const std::shared_ptr<TokenStream>& ts, TokenIt op, ExpPtr&& expr, UnaryOperatorPlacement operatorPlacement)
		: Expression(ts)
		, _op(op)
		, _expr(std::forward<ExpPtr>(expr))
		, _operatorPlacement(operatorPlacement)
	{
	}

	virtual TokenIt getFirstTokenIt() const override {
		if (_operatorPlacement == UnaryOperatorPlacement::Left)
			return _op;
		else
			return _expr->getFirstTokenIt();
	}

	virtual TokenIt getLastTokenIt() const override {
		if (_operatorPlacement == UnaryOperatorPlacement::Left)
			return _expr->getLastTokenIt();
		else
			return _op;
	}

	template <typename ExpT>
	Expression::Ptr cloneAs(const std::shared_ptr<TokenStream>& target) const
	{
		TokenIt newOp;
		Expression::Ptr newOperand;

		if (_operatorPlacement == UnaryOperatorPlacement::Left)
		{
			target->cloneAppend(getTokenStream(), getFirstTokenIt(), getOperator());
			newOp = getOperator()->clone(target.get());
			target->cloneAppend(getTokenStream(), std::next(getOperator()), getOperand()->getFirstTokenIt());
			newOperand = getOperand()->clone(target);
			target->cloneAppend(getTokenStream(), std::next(getOperand()->getLastTokenIt()), std::next(getLastTokenIt()));
		}
		else
		{
			target->cloneAppend(getTokenStream(), getFirstTokenIt(), getOperand()->getFirstTokenIt());
			newOperand = getOperand()->clone(target);
			target->cloneAppend(getTokenStream(), std::next(getOperand()->getLastTokenIt()), getOperator());
			newOp = getOperator()->clone(target.get());
			target->cloneAppend(getTokenStream(), std::next(getOperator()), std::next(getLastTokenIt()));
		}

		return std::make_shared<ExpT>(target, newOp, std::move(newOperand));
	}

private:
	TokenIt _op; ///< Unary operation symbol, std::string
	Expression::Ptr _expr; ///< Expression to apply operator on
	UnaryOperatorPlacement _operatorPlacement; ///< Determines if the operator should be printed before the expression
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
	template <typename ExpPtr>
	NotExpression(TokenIt op, ExpPtr&& expr) : UnaryOpExpression(op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Left) {}

	template <typename ExpPtr>
	NotExpression(const std::shared_ptr<TokenStream>& ts, TokenIt op, ExpPtr&& expr) : UnaryOpExpression(ts, op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Left) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<NotExpression>(target);
	}
};

/**
 * Class representing percentual operation.
 *
 * For example:
 * @code
 * 25%
 * @endcode
 */
class PercentualExpression : public UnaryOpExpression
{
public:
	template <typename ExpPtr>
	PercentualExpression(TokenIt op, ExpPtr&& expr) : UnaryOpExpression(op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Right) {}

	template <typename ExpPtr>
	PercentualExpression(const std::shared_ptr<TokenStream>& ts, TokenIt op, ExpPtr&& expr) : UnaryOpExpression(ts, op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Right) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<PercentualExpression>(target);
	}
};

/**
 * Class representing defined operation.
 *
 * For example:
 * @code
 * defined @str
 * @endcode
 */
class DefinedExpression : public UnaryOpExpression
{
public:
	template<typename ExpPtr>
	DefinedExpression(TokenIt op, ExpPtr &&expr) : UnaryOpExpression(op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Left) {}

	template<typename ExpPtr>
	DefinedExpression(const std::shared_ptr<TokenStream>& ts, TokenIt op, ExpPtr &&expr) : UnaryOpExpression(ts, op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Left) {}

	virtual VisitResult accept(Visitor *v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<DefinedExpression>(target);
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
	template <typename ExpPtr>
	UnaryMinusExpression(TokenIt op, ExpPtr&& expr) : UnaryOpExpression(op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Left) {}

	template <typename ExpPtr>
	UnaryMinusExpression(const std::shared_ptr<TokenStream>& ts, TokenIt op, ExpPtr&& expr) : UnaryOpExpression(ts, op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Left) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<UnaryMinusExpression>(target);
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
	template <typename ExpPtr>
	BitwiseNotExpression(TokenIt op, ExpPtr&& expr) : UnaryOpExpression(op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Left) {}

	template <typename ExpPtr>
	BitwiseNotExpression(const std::shared_ptr<TokenStream>& ts, TokenIt op, ExpPtr&& expr) : UnaryOpExpression(ts, op, std::forward<ExpPtr>(expr), UnaryOperatorPlacement::Left) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<BitwiseNotExpression>(target);
	}
};

/**
 * Abstract class representing some binary operation.
 */
class BinaryOpExpression : public Expression
{
public:
	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		return _left->getText(indent) + ' ' + _op->getString() + (_linebreak ? "\n" + indent : " ") + _right->getText(indent);
	}

	TokenIt getOperator() const { return _op; }
	const Expression::Ptr& getLeftOperand() const { return _left; }
	const Expression::Ptr& getRightOperand() const { return _right; }

	virtual TokenIt getFirstTokenIt() const override { return _left->getFirstTokenIt(); }
	virtual TokenIt getLastTokenIt() const override { return _right->getLastTokenIt(); }

	void setLeftOperand(const Expression::Ptr& left) { _left = left; }
	void setLeftOperand(Expression::Ptr&& left) { _left = std::move(left); }
	void setRightOperand(const Expression::Ptr& right) { _right = right; }
	void setRightOperand(Expression::Ptr&& right) { _right = std::move(right); }

protected:
	template <typename ExpPtr1, typename ExpPtr2>
	BinaryOpExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right, bool linebreak = false)
		: _op(op)
		, _left(std::forward<ExpPtr1>(left))
		, _right(std::forward<ExpPtr2>(right))
		, _linebreak(linebreak)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2>
	BinaryOpExpression(ExpPtr1&& left, const std::string& op, TokenType type, ExpPtr2&& right, bool linebreak = false)
		: _left(std::forward<ExpPtr1>(left))
		, _right(std::forward<ExpPtr2>(right))
		, _linebreak(linebreak)
	{
		_op = _tokenStream->emplace_back(type, op);
	}

	template <typename ExpPtr1, typename ExpPtr2>
	BinaryOpExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right, bool linebreak = false)
		: Expression(ts)
		, _op(op)
		, _left(std::forward<ExpPtr1>(left))
		, _right(std::forward<ExpPtr2>(right))
		, _linebreak(linebreak)
	{
	}

	template <typename ExpT>
	Expression::Ptr cloneAs(const std::shared_ptr<TokenStream>& target) const
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), getLeftOperand()->getFirstTokenIt());
		auto newLeftOperand = getLeftOperand()->clone(target);
		target->cloneAppend(getTokenStream(), std::next(getLeftOperand()->getLastTokenIt()), getOperator());
		auto newOp = getOperator()->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(getOperator()), getRightOperand()->getFirstTokenIt());
		auto newRightOperand = getRightOperand()->clone(target);
		target->cloneAppend(getTokenStream(), std::next(getRightOperand()->getLastTokenIt()), std::next(getLastTokenIt()));

		// Not all expressions expose linebreak
		auto result = std::make_shared<ExpT>(target, std::move(newLeftOperand), newOp, std::move(newRightOperand));
		result->_linebreak = _linebreak;
		return result;
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
	template <typename ExpPtr1, typename ExpPtr2>
	AndExpression(ExpPtr1&& left, TokenIt and_op, ExpPtr2&& right, bool linebreak = false) : BinaryOpExpression(std::forward<ExpPtr1>(left), and_op, std::forward<ExpPtr2>(right), linebreak) {}

	template <typename ExpPtr1, typename ExpPtr2>
	AndExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<AndExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	OrExpression(ExpPtr1&& left, TokenIt op_or, ExpPtr2&& right, bool linebreak = false) : BinaryOpExpression(std::forward<ExpPtr1>(left), op_or, std::forward<ExpPtr2>(right), linebreak) {}

	template <typename ExpPtr1, typename ExpPtr2>
	OrExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<OrExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	LtExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	LtExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<LtExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	GtExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	GtExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<GtExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	LeExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	LeExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<LeExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	GeExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	GeExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<GeExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	EqExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	EqExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<EqExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	NeqExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	NeqExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<NeqExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	ContainsExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	ContainsExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<ContainsExpression>(target);
	}
};

/**
 * Class representing icontains case-insensitive operation on two strings.
 *
 * For example:
 * @code
 * pe.sections[0] icontains "text"
 * @endcode
 */
class IcontainsExpression : public BinaryOpExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2>
	IcontainsExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	IcontainsExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<IcontainsExpression>(target);
	}
};

/**
 * Class representing contains operation on string and regular expression.
 *
 * For example:
 * @code
 * pe.sections[0].name matches /(text|data)/
 * @endcode
 */
class MatchesExpression : public BinaryOpExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2>
	MatchesExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	MatchesExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<MatchesExpression>(target);
	}
};

/**
 * Class representing startswith operation for string starting with relation.
 *
 * For example:
 * @code
 * pe.sections[0].name startswith ".t"
 * @endcode
 */
class StartsWithExpression : public BinaryOpExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2>
	StartsWithExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	StartsWithExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<StartsWithExpression>(target);
	}
};

/**
 * Class representing istartswith operation for case-insensitive string starting with relation.
 *
 * For example:
 * @code
 * pe.sections[0].name istartswith ".t"
 * @endcode
 */
class IstartsWithExpression : public BinaryOpExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2>
	IstartsWithExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	IstartsWithExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<IstartsWithExpression>(target);
	}
};

/**
 * Class representing endswith operation for string ending with relation.
 *
 * For example:
 * @code
 * pe.sections[0].name endswith "xt"
 * @endcode
 */
class EndsWithExpression : public BinaryOpExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2>
	EndsWithExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	EndsWithExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<EndsWithExpression>(target);
	}
};

/**
 * Class representing iendswith operation for case-insensitive string ending with relation.
 *
 * For example:
 * @code
 * pe.sections[0].name iendswith ".t"
 * @endcode
 */
class IendsWithExpression : public BinaryOpExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2>
	IendsWithExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	IendsWithExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<IendsWithExpression>(target);
	}
};

/**
 * Class representing iequals operation for case-insensitive string compare.
 *
 * For example:
 * @code
 * pe.sections[0].name iequals ".TEXT"
 * @endcode
 */
class IequalsExpression : public BinaryOpExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2>
	IequalsExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	IequalsExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<IequalsExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	PlusExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	PlusExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<PlusExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	MinusExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	MinusExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<MinusExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	MultiplyExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	MultiplyExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<MultiplyExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	DivideExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	DivideExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<DivideExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	ModuloExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	ModuloExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<ModuloExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	BitwiseXorExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	BitwiseXorExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<BitwiseXorExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	BitwiseAndExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	BitwiseAndExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<BitwiseAndExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	BitwiseOrExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	BitwiseOrExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<BitwiseOrExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	ShiftLeftExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	ShiftLeftExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<ShiftLeftExpression>(target);
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
	template <typename ExpPtr1, typename ExpPtr2>
	ShiftRightExpression(ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	template <typename ExpPtr1, typename ExpPtr2>
	ShiftRightExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& left, TokenIt op, ExpPtr2&& right) : BinaryOpExpression(ts, std::forward<ExpPtr1>(left), op, std::forward<ExpPtr2>(right)) {}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<ShiftRightExpression>(target);
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
	const Expression::Ptr& getIterable() const { return _iterable; }
	const Expression::Ptr& getBody() const { return _expr; }

	void setVariable(const Expression::Ptr& forExpr) { _forExpr = forExpr; }
	void setVariable(Expression::Ptr&& forExpr) { _forExpr = std::move(forExpr); }
	void setIterable(const Expression::Ptr& iterable) { _iterable = iterable; }
	void setIterable(Expression::Ptr&& iterable) { _iterable = std::move(iterable); }
	void setBody(const Expression::Ptr& expr) { _expr = expr; }
	void setBody(Expression::Ptr&& expr) { _expr = std::move(expr); }

protected:
	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForExpression(ExpPtr1&& forExpr, TokenIt of_in, ExpPtr2&& iterable, ExpPtr3&& expr)
		: _forExpr(std::forward<ExpPtr1>(forExpr))
		, _iterable(std::forward<ExpPtr2>(iterable))
		, _expr(std::forward<ExpPtr3>(expr))
		, _of_in(of_in)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2>
	ForExpression(ExpPtr1&& forExpr, TokenIt of_in, ExpPtr2&& iterable)
		: _forExpr(std::forward<ExpPtr1>(forExpr))
		, _iterable(std::forward<ExpPtr2>(iterable))
		, _expr(nullptr)
		, _of_in(of_in)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& forExpr, TokenIt of_in, ExpPtr2&& iterable, ExpPtr3&& expr)
		: Expression(ts)
		, _forExpr(std::forward<ExpPtr1>(forExpr))
		, _iterable(std::forward<ExpPtr2>(iterable))
		, _expr(std::forward<ExpPtr3>(expr))
		, _of_in(of_in)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2>
	ForExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& forExpr, TokenIt of_in, ExpPtr2&& iterable)
		: Expression(ts)
		, _forExpr(std::forward<ExpPtr1>(forExpr))
		, _iterable(std::forward<ExpPtr2>(iterable))
		, _expr(nullptr)
		, _of_in(of_in)
	{
	}

	Expression::Ptr _forExpr, _iterable, _expr;
	TokenIt _of_in;
};

/**
 * Class representing for loop over dictionary.
 *
 * For example:
 * @code
 * for all k, v in dome_dict : (  k == "foo" and v == "bar" )
 * @endcode
 */
class ForDictExpression : public ForExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForDictExpression(TokenIt for_token, ExpPtr1&& forExpr, TokenIt id1, TokenIt comma, TokenIt id2, TokenIt in, ExpPtr2&& dict, TokenIt left_bracket, ExpPtr3&& expr, TokenIt right_bracket)
		: ForExpression(std::forward<ExpPtr1>(forExpr), in, std::forward<ExpPtr2>(dict), std::forward<ExpPtr3>(expr))
		, _id1(id1)
		, _comma(comma)
		, _id2(id2)
		, _for (for_token)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForDictExpression(const std::shared_ptr<TokenStream>& ts, TokenIt for_token, ExpPtr1&& forExpr, TokenIt id1, TokenIt comma, TokenIt id2, TokenIt in, ExpPtr2&& dict, TokenIt left_bracket, ExpPtr3&& expr, TokenIt right_bracket)
		: ForExpression(ts, std::forward<ExpPtr1>(forExpr), in, std::forward<ExpPtr2>(dict), std::forward<ExpPtr3>(expr))
		, _id1(id1)
		, _comma(comma)
		, _id2(id2)
		, _for (for_token)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	const std::string& getId1() const { return _id1->getString(); }
	const std::string& getId2() const { return _id2->getString(); }

	void setId1(const std::string& id) { _id1->setValue(id); }
	void setId1(std::string&& id) { _id1->setValue(std::move(id)); }
	void setId2(const std::string& id) { _id2->setValue(id); }
	void setId2(std::string&& id) { _id2->setValue(std::move(id)); }

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		assert(_iterable);
		std::stringstream ss;
		ss << _for->getString() << " " << _forExpr->getText(indent) << " " << _id1->getString() << ", " << _id2->getString()
			<< " " << _of_in->getString() << " " << _iterable->getText(indent) << " : "
			<< _left_bracket->getString()<< " " << _expr->getText(indent) << " " << _right_bracket->getString();
		return ss.str();
	}

	virtual TokenIt getFirstTokenIt() const override { return _for; }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _for);
		auto newFor = _for->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_for), _forExpr->getFirstTokenIt());
		auto newForExpr = _forExpr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_forExpr->getLastTokenIt()), _id1);
		auto newId1 = _id1->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id1), _comma);
		auto newComma = _comma->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_comma), _id2);
		auto newId2 = _id2->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id2), _of_in);
		auto newOfIn = _of_in->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_of_in), _iterable->getFirstTokenIt());
		auto newIterable = _iterable->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_iterable->getLastTokenIt()), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_left_bracket), _expr->getFirstTokenIt());
		auto newBody = _expr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_expr->getLastTokenIt()), _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		return std::make_shared<ForDictExpression>(
			target,
			newFor,
			std::move(newForExpr),
			newId1,
			newComma,
			newId2,
			newOfIn,
			std::move(newIterable),
			newLb,
			std::move(newBody),
			newRb
		);
	}

private:
	TokenIt _id1; ///< Iterating identifier 1
	TokenIt _comma; ///< TokenIt of ','
	TokenIt _id2; ///< Iterating identifier 2
	TokenIt _for; ///< TokenIt of 'for'
	TokenIt _left_bracket; ///< TokenIt of '('
	TokenIt _right_bracket; ///< TokenIt of ')'
};

/**
 * Class representing for loop over integer set, integer range or array.
 *
 * For example:
 * @code
 * for all i in (1 .. 5) : ( #str[i] > 0 }
 * @endcode
 */
class ForArrayExpression : public ForExpression
{
public:
	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForArrayExpression(TokenIt for_token, ExpPtr1&& forExpr, TokenIt id, TokenIt in, ExpPtr2&& iterable, TokenIt left_bracket, ExpPtr3&& expr, TokenIt right_bracket)
		: ForExpression(std::forward<ExpPtr1>(forExpr), in, std::forward<ExpPtr2>(iterable), std::forward<ExpPtr3>(expr))
		, _id(id)
		, _for (for_token)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForArrayExpression(const std::shared_ptr<TokenStream>& ts, TokenIt for_token, ExpPtr1&& forExpr, TokenIt id, TokenIt in, ExpPtr2&& iterable, TokenIt left_bracket, ExpPtr3&& expr, TokenIt right_bracket)
		: ForExpression(ts, std::forward<ExpPtr1>(forExpr), in, std::forward<ExpPtr2>(iterable), std::forward<ExpPtr3>(expr))
		, _id(id)
		, _for (for_token)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	const std::string& getId() const { return _id->getString(); }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		assert(_iterable);
		std::stringstream ss;
		ss << _for->getString() << " " << _forExpr->getText(indent) << " " << _id->getString() << " "
			<< _of_in->getString() << " " << _iterable->getText(indent) << " : "
			<< _left_bracket->getString()<< " " << _expr->getText(indent) << " " << _right_bracket->getString();
		return ss.str();
	}

	virtual TokenIt getFirstTokenIt() const override { return _for; }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _for);
		auto newFor = _for->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_for), _forExpr->getFirstTokenIt());
		auto newForExpr = _forExpr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_forExpr->getLastTokenIt()), _id);
		auto newId = _id->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id), _of_in);
		auto newOfIn = _of_in->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_of_in), _iterable->getFirstTokenIt());
		auto newIterable = _iterable->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_iterable->getLastTokenIt()), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_left_bracket), _expr->getFirstTokenIt());
		auto newBody = _expr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_expr->getLastTokenIt()), _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		return std::make_shared<ForArrayExpression>(
			target,
			newFor,
			std::move(newForExpr),
			newId,
			newOfIn,
			std::move(newIterable),
			newLb,
			std::move(newBody),
			newRb
		);
	}

private:
	TokenIt _id; ///< Iterating identifier
	TokenIt _for; ///< TokenIt of 'for'
	TokenIt _left_bracket; ///< TokenIt of '('
	TokenIt _right_bracket; ///< TokenIt of ')'
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
	 * Constructor
	 */
	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForStringExpression(TokenIt for_token, ExpPtr1&& forExpr, TokenIt of, ExpPtr2&& set, TokenIt left_bracket, ExpPtr3&& expr, TokenIt right_bracket)
		: ForExpression(std::forward<ExpPtr1>(forExpr), of, std::forward<ExpPtr2>(set), std::forward<ExpPtr3>(expr))
		, _for (for_token)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	ForStringExpression(const std::shared_ptr<TokenStream>& ts, TokenIt for_token, ExpPtr1&& forExpr, TokenIt of, ExpPtr2&& set, TokenIt left_bracket, ExpPtr3&& expr, TokenIt right_bracket)
		: ForExpression(ts, std::forward<ExpPtr1>(forExpr), of, std::forward<ExpPtr2>(set), std::forward<ExpPtr3>(expr))
		, _for (for_token)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		std::stringstream ss;
		ss	<< _for->getString() << " " << _forExpr->getText(indent) << " "
			<< _of_in->getString() + " " << _iterable->getText(indent) << " : "
			<< _left_bracket->getString() << " " << _expr->getText(indent) << " " << _right_bracket->getString();
		return ss.str();
	}

	virtual TokenIt getFirstTokenIt() const override { return _for; }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _for);
		auto newFor = _for->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_for), _forExpr->getFirstTokenIt());
		auto newForExpr = _forExpr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_forExpr->getLastTokenIt()), _of_in);
		auto newOfIn = _of_in->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_of_in), _iterable->getFirstTokenIt());
		auto newIterable = _iterable->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_iterable->getLastTokenIt()), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_left_bracket), _expr->getFirstTokenIt());
		auto newBody = _expr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_expr->getLastTokenIt()), _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_right_bracket), std::next(getLastTokenIt()));
		return std::make_shared<ForStringExpression>(
			target,
			newFor,
			std::move(newForExpr),
			newOfIn,
			std::move(newIterable),
			newLb,
			std::move(newBody),
			newRb
		);
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
 * 
 * There can be also "in" with range:
 * @code
 * any of ($str1, $str2) in (0..10)
 * @endcode
 * 
 * Or "at" with offset (new in YARA 4.3):
 * @code
 * any of ($str1, $str2) at 100
 * @endcode
 */
class OfExpression : public ForExpression
{
public:
	/**
	 * Constructor
	 */
	template <typename ExpPtr1, typename ExpPtr2>
	OfExpression(ExpPtr1&& forExpr, TokenIt of, ExpPtr2&& set)
		: ForExpression(std::forward<ExpPtr1>(forExpr), of, std::forward<ExpPtr2>(set))
		, _location_symbol(std::nullopt)
		, _location(nullptr)
	{
	}
	/**
	 * Constructor
	 */
	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	OfExpression(ExpPtr1&& forExpr, TokenIt of, ExpPtr2&& set, TokenIt location_symbol, ExpPtr3&& location)
		: ForExpression(std::forward<ExpPtr1>(forExpr), of, std::forward<ExpPtr2>(set))
		, _location_symbol(location_symbol)
		, _location(std::forward<ExpPtr3>(location))
	{
	}

	template <typename ExpPtr1, typename ExpPtr2, typename ExpPtr3>
	OfExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& forExpr, TokenIt of, ExpPtr2&& set, const std::optional<TokenIt>& location_symbol, ExpPtr3&& location)
		: ForExpression(ts, std::forward<ExpPtr1>(forExpr), of, std::forward<ExpPtr2>(set))
		, _location_symbol(location_symbol)
		, _location(std::forward<ExpPtr3>(location))
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		std::string output = _forExpr->getText(indent) + " " + _of_in->getString() + " " + _iterable->getText(indent);
		if (_location && _location_symbol.has_value())
			output +=  " " + _location_symbol.value()->getString() + " " + _location->getText(indent);
		return output;
	}

	/**
	 * Getter for location expression
	 * @return Return location expression
	 */
	const Expression::Ptr& getLocationExpression() const { return _location; }
	void setLocationExpression(const Expression::Ptr& location) { _location = location; }
	void setLocationExpression(Expression::Ptr&& location) { _location = std::move(location); }
	
	/**
	 * Same as OfExpression::getLocationExpression
	 * @note It is named as getRangeExpression to preserve backward compatibility
	 */
	const Expression::Ptr& getRangeExpression() const { return getLocationExpression(); }
	void setRangeExpression(const Expression::Ptr& range) { setLocationExpression(range); }
	void setRangeExpression(Expression::Ptr&& range) { setLocationExpression(std::move(range)); }

	virtual TokenIt getFirstTokenIt() const override { return _forExpr->getFirstTokenIt(); }
	virtual TokenIt getLastTokenIt() const override { return _location ? _location->getLastTokenIt() : _iterable->getLastTokenIt(); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _forExpr->getFirstTokenIt());
		auto newForExpr = _forExpr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_forExpr->getLastTokenIt()), _of_in);
		auto newOfIn = _of_in->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_of_in), _iterable->getFirstTokenIt());
		auto newIterable = _iterable->clone(target);

		std::optional<TokenIt> newLocationSymbol;
		Expression::Ptr newLocation;
		if (_location && _location_symbol.has_value())
		{
			auto loc = _location_symbol.value();
			target->cloneAppend(getTokenStream(), std::next(_iterable->getLastTokenIt()), loc);
			newLocationSymbol = loc->clone(target.get());
			target->cloneAppend(getTokenStream(), std::next(loc), _location->getFirstTokenIt());
			newLocation = _location->clone(target);
			target->cloneAppend(getTokenStream(), std::next(_location->getLastTokenIt()), std::next(getLastTokenIt()));
		}
		else
		{
			target->cloneAppend(getTokenStream(), std::next(_iterable->getLastTokenIt()), std::next(getLastTokenIt()));
		}

		return std::make_shared<OfExpression>(
			target,
			std::move(newForExpr),
			newOfIn,
			std::move(newIterable),
			newLocationSymbol,
			std::move(newLocation)
		);
	}

private:
	// Range and offset expression is stored in the same member _location, there cannot be offset and range at the same time
	std::optional<TokenIt> _location_symbol; ///< Token holding "in" or "at"
	Expression::Ptr _location; ///< Range expression ("in" <range>) or offset expression ("at" <offset>)
};

/**
 * Class representing an iterable, which is an array of expressions typically
 * used with an of operator
 *
 * For example:
 * @code
 * all of [ true, false, true ]
 *        ^^^^^^^^^^^^^^^^^^^^^
 * @endcode
 */
class IterableExpression : public Expression
{
public:
	/**
	 * Constructor
	 */
	template <typename ExpPtrVector>
	IterableExpression(TokenIt left_square_bracket, ExpPtrVector&& elements, TokenIt right_square_bracket)
		: _left_square_bracket(left_square_bracket)
		, _elements(std::forward<ExpPtrVector>(elements))
		, _right_square_bracket(right_square_bracket)
	{
	}

	template <typename ExpPtrVector>
	IterableExpression(const std::shared_ptr<TokenStream>& ts, TokenIt left_square_bracket, ExpPtrVector&& elements, TokenIt right_square_bracket)
		: Expression(ts)
		, _left_square_bracket(left_square_bracket)
		, _elements(std::forward<ExpPtrVector>(elements))
		, _right_square_bracket(right_square_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		std::ostringstream ss;
		ss << _left_square_bracket->getString();
		for (const auto& elem : _elements)
			ss << elem->getText(indent) << ", ";
		ss <<_right_square_bracket->getString();

		// Remove last ', ' from the result.
		auto text = ss.str();
		text.erase(text.length() - 3, 2);
		return text;
	}

	const std::vector<Expression::Ptr>& getElements() const { return _elements; }

	virtual TokenIt getFirstTokenIt() const override { return _left_square_bracket; }
	virtual TokenIt getLastTokenIt() const override { return _right_square_bracket; }

	void setElements(const std::vector<Expression::Ptr>& elements)
	{
		_elements = elements;
	}

	void setElements(std::vector<Expression::Ptr>&& elements)
	{
		_elements = std::move(elements);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		std::vector<Expression::Ptr> newElements;
		newElements.reserve(_elements.size());

		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _left_square_bracket);
		auto newLsb = _left_square_bracket->clone(target.get());

		TokenIt previousEnd = std::next(_left_square_bracket);
		for (const auto& elem : _elements)
		{
			target->cloneAppend(getTokenStream(), previousEnd, elem->getFirstTokenIt());
			auto newElem = elem->clone(target);
			newElements.push_back(std::move(newElem));
			previousEnd = std::next(elem->getLastTokenIt());
		}

		target->cloneAppend(getTokenStream(), previousEnd, _right_square_bracket);
		auto newRsb = _right_square_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(newRsb), std::next(getLastTokenIt()));

		return std::make_shared<IterableExpression>(
			target,
			newLsb,
			std::move(newElements),
			newRsb
		);
	}

private:
	TokenIt _left_square_bracket;
	std::vector<Expression::Ptr> _elements; ///< Elements of the set
	TokenIt _right_square_bracket;
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
	/**
	 * Constructor
	 */
	template <typename ExpPtrVector>
	SetExpression(TokenIt left_bracket, ExpPtrVector&& elements, TokenIt right_bracket)
		: _left_bracket(left_bracket)
		, _elements(std::forward<ExpPtrVector>(elements))
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtrVector>
	SetExpression(const std::shared_ptr<TokenStream>& ts, TokenIt left_bracket, ExpPtrVector&& elements, TokenIt right_bracket)
		: Expression(ts)
		, _left_bracket(left_bracket)
		, _elements(std::forward<ExpPtrVector>(elements))
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
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

	virtual TokenIt getFirstTokenIt() const override { return _left_bracket; }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	void setElements(const std::vector<Expression::Ptr>& elements)
	{
		_elements = elements;
	}

	void setElements(std::vector<Expression::Ptr>&& elements)
	{
		_elements = std::move(elements);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		std::vector<Expression::Ptr> newElements;
		newElements.reserve(_elements.size());

		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());

		TokenIt previousEnd = std::next(_left_bracket);
		for (const auto& elem : _elements)
		{
			target->cloneAppend(getTokenStream(), previousEnd, elem->getFirstTokenIt());
			auto newElem = elem->clone(target);
			newElements.push_back(std::move(newElem));
			previousEnd = std::next(elem->getLastTokenIt());
		}

		target->cloneAppend(getTokenStream(), previousEnd, _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_right_bracket), std::next(getLastTokenIt()));

		return std::make_shared<SetExpression>(
			target,
			newLb,
			std::move(newElements),
			newRb
		);
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
	/**
	 * Constructor
	 */
	template <typename ExpPtr1, typename ExpPtr2>
	RangeExpression(TokenIt left_bracket, ExpPtr1&& low, TokenIt double_dot, ExpPtr2&& high, TokenIt right_bracket)
		: _left_bracket(left_bracket)
		, _low(std::forward<ExpPtr1>(low))
		, _double_dot(double_dot)
		, _high(std::forward<ExpPtr2>(high))
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2>
	RangeExpression(const std::shared_ptr<TokenStream>& ts, TokenIt left_bracket, ExpPtr1&& low, TokenIt double_dot, ExpPtr2&& high, TokenIt right_bracket)
		: Expression(ts)
		, _left_bracket(left_bracket)
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

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		return _left_bracket->getString() + _low->getText(indent) + " " + _double_dot->getString() + " " + _high->getText(indent) + _right_bracket->getString();
	}

	const Expression::Ptr& getLow() const { return _low; }
	const Expression::Ptr& getHigh() const { return _high; }

	virtual TokenIt getFirstTokenIt() const override { return _left_bracket; }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	void setLow(const Expression::Ptr& low) { _low = low; }
	void setLow(Expression::Ptr&& low) { _low = std::move(low); }
	void setHigh(const Expression::Ptr& high) { _high = high; }
	void setHigh(Expression::Ptr&& high) { _high = std::move(high); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_left_bracket), _low->getFirstTokenIt());
		auto newLow = _low->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_low->getLastTokenIt()), _double_dot);
		auto newDoubleDot = _double_dot->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_double_dot), _high->getFirstTokenIt());
		auto newHigh = _high->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_high->getLastTokenIt()), _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_right_bracket), std::next(getLastTokenIt()));
		return std::make_shared<RangeExpression>(target, newLb, std::move(newLow), newDoubleDot, std::move(newHigh), newRb);
	}

private:
	TokenIt _left_bracket; ///< '('
	Expression::Ptr _low;  ///< Upper bound of the range
	TokenIt _double_dot; ///< '..'
	Expression::Ptr _high; ///< Lower bound of the range
	TokenIt _right_bracket; ///< ')'
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
	/**
	 * Constructors
	 */
	IdExpression(TokenIt symbolToken)
		: _symbol(symbolToken->getSymbol())
		, _symbolToken(symbolToken)
	{
	}

	IdExpression(const std::shared_ptr<TokenStream>& ts, TokenIt symbolToken)
		: Expression(ts)
		, _symbol(symbolToken->getSymbol())
		, _symbolToken(symbolToken)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = std::string{}) const override
	{
		assert(_symbol);
		return _symbol->getName();
	}

	const std::shared_ptr<Symbol>& getSymbol() const
	{
		return _symbol;
	}

	TokenIt getSymbolToken() const
	{
		return _symbolToken;
	}

	virtual TokenIt getFirstTokenIt() const override { return _symbolToken; }
	virtual TokenIt getLastTokenIt() const override { return _symbolToken; }

	void setSymbol(const std::shared_ptr<Symbol>& symbol)
	{
		_symbol = symbol;
		_symbolToken->setValue(_symbol);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _symbolToken);
		auto newSymbol = _symbolToken->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_symbolToken), std::next(getLastTokenIt()));
		return std::make_shared<IdExpression>(target, newSymbol);
	}

protected:
	IdExpression(const std::shared_ptr<Symbol>& symbol)
		: _symbol(symbol)
	{
	}

	std::shared_ptr<Symbol> _symbol; ///< Symbol of the identifier
	TokenIt _symbolToken; ///< Token of the identifier
};

/**
 * Class representing identifier wildcard expression. The only place where identifier wildcards
 * can be used are N of (<rule_set>) expressions.
 *
 * For example:
 * @code
 * 2 of (rule_prefix_*)
 *       ^^^^^^^^^^^^^
 * @endcode
 */
class IdWildcardExpression : public Expression
{
public:
	/**
	 * Constructors
	 */
	IdWildcardExpression(TokenIt id, TokenIt wildcard) : _id(id), _wildcard(wildcard)
	{
	}

	IdWildcardExpression(const std::shared_ptr<TokenStream>& ts, TokenIt id, TokenIt wildcard) : Expression(ts), _id(id), _wildcard(wildcard)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = std::string{}) const override
	{
		return getId() + _wildcard->getString();
	}

	const std::string& getId() const { return _id->getString(); }

	void setId(const std::string& id) { _id->setValue(id); }
	void setId(std::string&& id) { _id->setValue(std::move(id)); }

	virtual TokenIt getFirstTokenIt() const override { return _id; }
	virtual TokenIt getLastTokenIt() const override { return _wildcard; }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _id);
		auto newId = _id->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_id), _wildcard);
		auto newWildcard = _wildcard->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_wildcard), std::next(getLastTokenIt()));
		return std::make_shared<IdWildcardExpression>(target, newId, newWildcard);
	}

protected:
	TokenIt _id; ///< Token of the identifier wildcard
	TokenIt _wildcard; ///< Token of the wildcard symbol
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
	template <typename ExpPtr>
	StructAccessExpression(ExpPtr&& structure, TokenIt dot, TokenIt symbol)
		: IdExpression(symbol)
		, _structure(std::forward<ExpPtr>(structure))
		, _dot(dot)
	{
	}

	template <typename ExpPtr>
	StructAccessExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr&& structure, TokenIt dot, TokenIt symbol)
		: IdExpression(ts, symbol)
		, _structure(std::forward<ExpPtr>(structure))
		, _dot(dot)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		if (_symbol)
			return _structure->getText(indent) + _dot->getString() + _symbol->getName();
		return _structure->getText(indent) + _dot->getString();
	}

	const Expression::Ptr& getStructure() const { return _structure; }

	virtual TokenIt getFirstTokenIt() const override { return _structure->getFirstTokenIt(); }
	virtual TokenIt getLastTokenIt() const override { return _symbolToken; }

	void setStructure(const Expression::Ptr& structure) { _structure = structure; }
	void setStructure(Expression::Ptr&& structure) { _structure = std::move(structure); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _structure->getFirstTokenIt());
		auto newStruct = _structure->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_structure->getLastTokenIt()), _dot);
		auto newDot = _dot->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_dot), _symbolToken);
		auto newSymbol = _symbolToken->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_symbolToken), std::next(getLastTokenIt()));
		return std::make_shared<StructAccessExpression>(target, std::move(newStruct), newDot, newSymbol);
	}

private:
	Expression::Ptr _structure; ///< Structure identifier expression
	TokenIt _dot; ///< '.'
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
	template <typename ExpPtr1, typename ExpPtr2>
	ArrayAccessExpression(const std::shared_ptr<Symbol>& symbol, ExpPtr1&& array, TokenIt left_bracket, ExpPtr2&& accessor, TokenIt right_bracket)
		: IdExpression(symbol)
		, _array(std::forward<ExpPtr1>(array))
		, _left_bracket(left_bracket)
		, _accessor(std::forward<ExpPtr2>(accessor))
		, _right_bracket(right_bracket)
	{
		_symbolToken = std::static_pointer_cast<const IdExpression>(_array)->getSymbolToken();
	}

	template <typename ExpPtr1, typename ExpPtr2>
	ArrayAccessExpression(ExpPtr1&& array, TokenIt left_bracket, ExpPtr2&& accessor, TokenIt right_bracket)
		: IdExpression(std::static_pointer_cast<const IdExpression>(array)->getSymbolToken())
		, _array(std::forward<ExpPtr1>(array))
		, _left_bracket(left_bracket)
		, _accessor(std::forward<ExpPtr2>(accessor))
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtr1, typename ExpPtr2>
	ArrayAccessExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr1&& array, TokenIt left_bracket, ExpPtr2&& accessor, TokenIt right_bracket)
		: IdExpression(ts, std::static_pointer_cast<const IdExpression>(array)->getSymbolToken())
		, _array(std::forward<ExpPtr1>(array))
		, _left_bracket(left_bracket)
		, _accessor(std::forward<ExpPtr2>(accessor))
		, _right_bracket(right_bracket)
	{
		_symbolToken = std::static_pointer_cast<const IdExpression>(_array)->getSymbolToken();
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		return _array->getText(indent) + _left_bracket->getString() + _accessor->getText(indent) + _right_bracket->getString();
	}

	const Expression::Ptr& getArray() const { return _array; }
	const Expression::Ptr& getAccessor() const { return _accessor; }

	virtual TokenIt getFirstTokenIt() const override { return _array->getFirstTokenIt(); }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	void setArray(const Expression::Ptr& array) { _array = array; }
	void setArray(Expression::Ptr&& array) { _array = std::move(array); }
	void setAccessor(const Expression::Ptr& accessor) { _accessor = accessor; }
	void setAccessor(Expression::Ptr&& accessor) { _accessor = std::move(accessor); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _array->getFirstTokenIt());
		auto newArray = _array->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_array->getLastTokenIt()), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_left_bracket), _accessor->getFirstTokenIt());
		auto newAccessor = _accessor->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_accessor->getLastTokenIt()), _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_right_bracket), std::next(getLastTokenIt()));
		return std::make_shared<ArrayAccessExpression>(target, std::move(newArray), newLb, std::move(newAccessor), newRb);
	}

private:
	Expression::Ptr _array; ///< Array identifier expression
	TokenIt _left_bracket; ///< '['
	Expression::Ptr _accessor; ///< Accessor expression (expression enclosed in [])
	TokenIt _right_bracket; ///< ']'
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
	template <typename ExpPtr, typename ExpPtrVector>
	FunctionCallExpression(ExpPtr&& func, TokenIt left_bracket, ExpPtrVector&& args, TokenIt right_bracket)
		: IdExpression(std::static_pointer_cast<const IdExpression>(func)->getSymbolToken())
		, _func(std::forward<ExpPtr>(func))
		, _left_bracket(left_bracket)
		, _args(std::forward<ExpPtrVector>(args))
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtr, typename ExpPtrVector>
	FunctionCallExpression(const std::shared_ptr<TokenStream>& ts, ExpPtr&& func, TokenIt left_bracket, ExpPtrVector&& args, TokenIt right_bracket)
		: IdExpression(ts, std::static_pointer_cast<const IdExpression>(func)->getSymbolToken())
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

	virtual std::string getText(const std::string& indent = std::string{}) const override
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

	virtual TokenIt getFirstTokenIt() const override { return _func->getFirstTokenIt(); }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	void setFunction(const Expression::Ptr& func) { _func = func; }
	void setFunction(Expression::Ptr&& func) { _func = std::move(func); }
	void setArguments(const std::vector<Expression::Ptr>& args) { _args = args; }
	void setArguments(std::vector<Expression::Ptr>&& args) { _args = std::move(args); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		std::vector<Expression::Ptr> newArgs;
		newArgs.reserve(_args.size());

		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _func->getFirstTokenIt());
		auto newFunc = _func->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_func->getLastTokenIt()), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());

		TokenIt previousEnd = std::next(_left_bracket);
		for (const auto& arg : _args)
		{
			target->cloneAppend(getTokenStream(), previousEnd, arg->getFirstTokenIt());
			auto newArg = arg->clone(target);
			newArgs.push_back(std::move(newArg));
			previousEnd = std::next(arg->getLastTokenIt());
		}

		target->cloneAppend(getTokenStream(), previousEnd, _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_right_bracket), std::next(getLastTokenIt()));
		return std::make_shared<FunctionCallExpression>(target, std::move(newFunc), newLb, std::move(newArgs), newRb);
	}

private:
	Expression::Ptr _func; ///< Function identifier expression
	TokenIt _left_bracket; ///< '('
	std::vector<Expression::Ptr> _args; ///< Arguments expressions
	TokenIt _right_bracket; ///< ')'
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

	LiteralExpression() : _valid(false) {}
	LiteralExpression(TokenIt value) : _value(value) {}
	LiteralExpression(const std::shared_ptr<TokenStream>& ts, TokenIt value)
		: Expression(ts)
		, _value(value)
	{
	}

	virtual LiteralType getValue() const = 0;

	virtual std::string getText(const std::string& /*indent*/ = std::string{}) const override
	{
		if (_valid)
			return _value->getText();
		else
			return std::string();
	}

	virtual TokenIt getFirstTokenIt() const override { return _value; }
	virtual TokenIt getLastTokenIt() const override { return _value; }

	void clear()
	{
		if (_valid)
			_tokenStream->erase(_value);
	}

protected:
	template <typename ExpT>
	Expression::Ptr cloneAs(const std::shared_ptr<TokenStream>& target) const
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _value);
		auto newValue = _value->clone(target.get());
		target->cloneAppend(getTokenStream(), _value, std::move(getLastTokenIt()));
		return std::make_shared<ExpT>(target, newValue);
	}

	bool _valid = true; ///< Set if _value is valid
	TokenIt _value; ///< Value of the literal
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
		if (value)
			_value = _tokenStream->emplace_back(TokenType::BOOL_TRUE, value, "true");
		else
			_value = _tokenStream->emplace_back(TokenType::BOOL_FALSE, value, "false");
		_valid = true;
	}

	BoolLiteralExpression(const std::shared_ptr<TokenStream>& ts, TokenIt value)
		: LiteralExpression<bool>(ts, value)
	{
	}

	virtual LiteralType getValue() const override
	{
		return _value->getBool();
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<BoolLiteralExpression>(target);
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
	StringLiteralExpression(const std::shared_ptr<TokenStream>& ts, TokenIt value)
		: LiteralExpression<std::string>(ts, value)
	{
	}

	virtual LiteralType getValue() const override
	{
		return _value->getString();
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<StringLiteralExpression>(target);
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

	IntLiteralExpression(const std::shared_ptr<TokenStream>& ts, TokenIt value)
		: LiteralExpression<uint64_t>(ts, value)
	{
	}

	virtual LiteralType getValue() const override
	{
		return _value->getUInt();
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<IntLiteralExpression>(target);
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
	DoubleLiteralExpression(TokenIt value)
		: LiteralExpression<double>(value)
	{
	}

	DoubleLiteralExpression(const std::shared_ptr<TokenStream>& ts, TokenIt value)
		: LiteralExpression<double>(ts, value)
	{
	}

	virtual LiteralType getValue() const override
	{
		return _value->getFloat();
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<DoubleLiteralExpression>(target);
	}
};

/**
 * Abstract class representing expression that is formed just of one keyword.
 */
class KeywordExpression : public Expression
{
public:
	virtual std::string getText(const std::string& /*indent*/ = std::string{}) const override
	{
		return _keyword->getString();
	}

	virtual TokenIt getFirstTokenIt() const override { return _keyword; }
	virtual TokenIt getLastTokenIt() const override { return _keyword; }

protected:
	KeywordExpression() = default;
	KeywordExpression(TokenIt keyword)
		: _keyword(keyword)
	{
		assert(keyword->isString());
	}

	KeywordExpression(const std::shared_ptr<TokenStream>& ts, TokenIt keyword)
		: Expression(ts)
		, _keyword(keyword)
	{
		assert(keyword->isString());
	}

	template <typename ExpT>
	Expression::Ptr cloneAs(const std::shared_ptr<TokenStream>& target) const
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _keyword);
		auto newKeyword = _keyword->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_keyword), std::next(getLastTokenIt()));
		return std::make_shared<ExpT>(target, newKeyword);
	}

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
	FilesizeExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}
	FilesizeExpression(const std::shared_ptr<TokenStream>& ts, TokenIt t)
		: KeywordExpression(ts, t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<FilesizeExpression>(target);
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
	EntrypointExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}
	EntrypointExpression(const std::shared_ptr<TokenStream>& ts, TokenIt t)
		: KeywordExpression(ts, t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<EntrypointExpression>(target);
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
	AllExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}
	AllExpression(const std::shared_ptr<TokenStream>& ts, TokenIt t)
		: KeywordExpression(ts, t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<AllExpression>(target);
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
	AnyExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}
	AnyExpression(const std::shared_ptr<TokenStream>& ts, TokenIt t)
		: KeywordExpression(ts, t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<AnyExpression>(target);
	}
};

/**
 * Class representing 'none' expression. Can be used in conjunction with for loops indicating that for loop
 * needs to be evaluated false for all variables in the referenced set. This expression does not have a type.
 *
 * For example:
 * @code
 * none of them
 * ^^^^
 * @endcode
 */
class NoneExpression : public KeywordExpression
{
public:
	NoneExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}
	NoneExpression(const std::shared_ptr<TokenStream>& ts, TokenIt t)
		: KeywordExpression(ts, t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<NoneExpression>(target);
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
	ThemExpression(TokenIt t)
		: KeywordExpression(t)
	{
	}
	ThemExpression(const std::shared_ptr<TokenStream>& ts, TokenIt t)
		: KeywordExpression(ts, t)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		return cloneAs<ThemExpression>(target);
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
	 * Constructor
	 *
	 * @param TokenIt left_bracket.
	 * @param Expression::Ptr expr  argument inside the brackets.
	 * @param TokenIt right_bracket.
	 * @param bool linebreak.
	 */
	template <typename ExpPtr>
	ParenthesesExpression(TokenIt left_bracket, ExpPtr&& expr, TokenIt right_bracket, bool linebreak = false)
		: _expr(std::forward<ExpPtr>(expr))
		, _linebreak(linebreak)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtr>
	ParenthesesExpression(const std::shared_ptr<TokenStream>& ts, TokenIt left_bracket, ExpPtr&& expr, TokenIt right_bracket, bool linebreak = false)
		: Expression(ts)
		, _expr(std::forward<ExpPtr>(expr))
		, _linebreak(linebreak)
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		if (_linebreak)
		{
			auto newIndent = indent + '\t';
			return _left_bracket->getString() + '\n' + newIndent + _expr->getText(newIndent) + '\n' + indent + _right_bracket->getString();
		}

		return _left_bracket->getString() + _expr->getText(indent) + _right_bracket->getString();
	}

	const Expression::Ptr& getEnclosedExpression() const { return _expr; }

	virtual TokenIt getFirstTokenIt() const override { return _left_bracket; }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	void setEnclosedExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setEnclosedExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_left_bracket), _expr->getFirstTokenIt());
		auto newExpr = _expr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_expr->getLastTokenIt()), _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_right_bracket), std::next(getLastTokenIt()));
		return std::make_shared<ParenthesesExpression>(target, newLb, std::move(newExpr), newRb, _linebreak);
	}

private:
	Expression::Ptr _expr; ///< Enclosed expression
	bool _linebreak; ///< Put linebreak after opening and before closing parentheses and indent content by one more level.
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
	 * Constructor
	 *
	 * @param TokenIt func  name of the function.
	 * @param TokenIt left_bracket.
	 * @param Expression::Ptr expr  argument of the function.
	 * @param TokenIt right_bracket.
	 */
	template <typename ExpPtr>
	IntFunctionExpression(TokenIt func, TokenIt left_bracket, ExpPtr&& expr, TokenIt right_bracket)
		: _func(func)
		, _expr(std::forward<ExpPtr>(expr))
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	template <typename ExpPtr>
	IntFunctionExpression(const std::shared_ptr<TokenStream>& ts, TokenIt func, TokenIt left_bracket, ExpPtr&& expr, TokenIt right_bracket)
		: Expression(ts)
		, _func(func)
		, _expr(std::forward<ExpPtr>(expr))
		, _left_bracket(left_bracket)
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		return _func->getString() + _left_bracket->getString() + _expr->getText(indent) + _right_bracket->getString();
	}

	const std::string& getFunction() const { return _func->getString(); }
	const Expression::Ptr& getArgument() const { return _expr; }

	virtual TokenIt getFirstTokenIt() const override { return _func; }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	void setFunction(const std::string& func) { _func->setValue(func); }
	void setFunction(std::string&& func) { _func->setValue(std::move(func)); }
	void setArgument(const Expression::Ptr& expr) { _expr = expr; }
	void setArgument(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _func);
		auto newFunc = _func->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_func), _left_bracket);
		auto newLb = _left_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_left_bracket), _expr->getFirstTokenIt());
		auto newExpr = _expr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_expr->getLastTokenIt()), _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_right_bracket), std::next(getLastTokenIt()));
		return std::make_shared<IntFunctionExpression>(target, newFunc, newLb, std::move(newExpr), newRb);
	}

private:
	TokenIt _func; ///< Function identifier
	Expression::Ptr _expr; ///< Function argument
	TokenIt _left_bracket; ///< left parentheses token
	TokenIt _right_bracket; ///< right parentheses token
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
	template <typename S>
	RegexpExpression(S&& regexp)
		: _regexp(std::forward<S>(regexp))
	{
		_tokenStream = _regexp->getTokenStream();
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual std::string getText(const std::string& /*indent*/ = std::string{}) const override { return _regexp->getText(); }

	const std::shared_ptr<Regexp>& getRegexpString() const { return _regexp; }

	virtual TokenIt getFirstTokenIt() const override { return _regexp->getFirstTokenIt(); }
	virtual TokenIt getLastTokenIt() const override { return _regexp->getLastTokenIt(); }

	void setRegexpString(const std::shared_ptr<Regexp>& regexp) { _regexp = regexp; }
	void setRegexpString(std::shared_ptr<Regexp>&& regexp) { _regexp = std::move(regexp); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		auto newRegexp = _regexp->clone(target);
		return std::make_shared<RegexpExpression>(std::move(newRegexp));
	}

private:
	std::shared_ptr<Regexp> _regexp; ///< Regular expression string
};


/**
 * Class representing variable definition within with expression.
 *
 * For example:
 * @code
 * with last_section = pe.sections[pe.number_of_sections - 1] : ( ... )
 *      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * @endcode
 */
class VariableDefExpression : public Expression
{
public:
	template <typename ExpPtr>
	VariableDefExpression(TokenIt name, ExpPtr&& expr)
		: _name(name)
		, _expr(std::forward<ExpPtr>(expr))
	{
	}

	template <typename ExpPtr>
	VariableDefExpression(const std::shared_ptr<TokenStream>& ts, TokenIt name, ExpPtr&& expr)
		: Expression(ts)
		, _name(name)
		, _expr(std::forward<ExpPtr>(expr))
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual TokenIt getFirstTokenIt() const override { return _name; }
	virtual TokenIt getLastTokenIt() const override { return _expr->getLastTokenIt(); }

	const std::string& getName() const { return _name->getString(); }
	const Expression::Ptr& getExpression() const { return _expr; }

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		return getName() + " = " + _expr->getText(indent);
	}

	void setName(const std::string& name) { _name->setValue(name); }
	void setName(std::string&& name) { _name->setValue(std::move(name)); }
	void setExpression(const Expression::Ptr& expr) { _expr = expr; }
	void setExpression(Expression::Ptr&& expr) { _expr = std::move(expr); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _name);
		auto newName = _name->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_name), _expr->getFirstTokenIt());
		auto newExpr = _expr->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_expr->getLastTokenIt()), std::next(getLastTokenIt()));
		return std::make_shared<VariableDefExpression>(target, newName, std::move(newExpr));
	}

private:
	TokenIt _name;
	Expression::Ptr _expr;
};

/**
 * Class representing with variable expression.
 *
 * For example:
 * @code
 * with last_section = pe.sections[pe.number_of_sections - 1] : ( ... )
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * @endcode
 */
class WithExpression : public Expression
{
public:
	template <typename VarVector, typename ExpPtr>
	WithExpression(TokenIt with, VarVector&& vars, TokenIt left_bracket, ExpPtr&& body, TokenIt right_bracket)
		: _with(with)
		, _vars(std::forward<VarVector>(vars))
		, _left_bracket(left_bracket)
		, _body(std::forward<ExpPtr>(body))
		, _right_bracket(right_bracket)
	{
	}

	template <typename VarVector, typename ExpPtr>
	WithExpression(const std::shared_ptr<TokenStream>& ts, TokenIt with, VarVector&& vars, TokenIt left_bracket, ExpPtr&& body, TokenIt right_bracket)
		: Expression(ts)
		, _with(with)
		, _vars(std::forward<VarVector>(vars))
		, _left_bracket(left_bracket)
		, _body(std::forward<ExpPtr>(body))
		, _right_bracket(right_bracket)
	{
	}

	virtual VisitResult accept(Visitor* v) override
	{
		return v->visit(this);
	}

	virtual TokenIt getFirstTokenIt() const override { return _with; }
	virtual TokenIt getLastTokenIt() const override { return _right_bracket; }

	const std::vector<Expression::Ptr>& getVariables() const { return _vars; }
	const Expression::Ptr& getBody() const { return _body; }

	virtual std::string getText(const std::string& indent = std::string{}) const override
	{
		std::ostringstream ss;
		ss << "with ";
		for (auto itr = _vars.begin(), end = _vars.end(); itr != end; ++itr)
		{
			auto& expr = *itr;
			ss << expr->getText(indent);
			if (itr + 1 != end)
				ss << ", ";
			else
				ss << " : ";
		}
		ss << "(" << _body->getText(indent) << ")";
		return ss.str();
	}

	void setVariables(const std::vector<Expression::Ptr>& vars) { _vars = vars; }
	void setVariables(std::vector<Expression::Ptr>&& vars) { _vars = std::move(vars); }

	void setBody(const Expression::Ptr& body) { _body = body; }
	void setBody(Expression::Ptr&& body) { _body = std::move(body); }

	virtual Expression::Ptr clone(const std::shared_ptr<TokenStream>& target) const override
	{
		std::vector<Expression::Ptr> newVars;
		newVars.reserve(_vars.size());

		target->cloneAppend(getTokenStream(), getFirstTokenIt(), _with);
		auto newWith = _with->clone(target.get());

		TokenIt previousEnd = std::next(_with);
		for (const auto& var : _vars)
		{
			target->cloneAppend(getTokenStream(), previousEnd, var->getFirstTokenIt());
			auto newVar = var->clone(target);
			newVars.push_back(std::move(newVar));
			previousEnd = std::next(var->getLastTokenIt());
		}

		target->cloneAppend(getTokenStream(), previousEnd, _left_bracket);
		auto newLb = _left_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_left_bracket), _body->getFirstTokenIt());
		auto newBody = _body->clone(target);
		target->cloneAppend(getTokenStream(), std::next(_body->getLastTokenIt()), _right_bracket);
		auto newRb = _right_bracket->clone(target.get());
		target->cloneAppend(getTokenStream(), std::next(_right_bracket), std::next(getLastTokenIt()));

		return std::make_shared<WithExpression>(
			target,
			newWith,
			std::move(newVars),
			newLb,
			std::move(newBody),
			newRb
		);
	}

private:
	TokenIt _with;
	std::vector<Expression::Ptr> _vars;
	TokenIt _left_bracket;
	Expression::Ptr _body;
	TokenIt _right_bracket;
};

}
