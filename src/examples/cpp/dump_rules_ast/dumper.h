/**
 * @file src/examples/dump_rules_ast/dumper.h
 * @brief Implementation of AST dumper.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "yaramod/utils/observing_visitor.h"

class Dumper : public yaramod::ObservingVisitor
{
public:
	Dumper() : _indent(0) {}

	virtual yaramod::VisitResult visit(yaramod::StringExpression* expr) override
	{
		dump("String", expr, " id=", expr->getId());
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::StringWildcardExpression* expr) override
	{
		dump("StringWildcard", expr, " id=", expr->getId());
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::StringAtExpression* expr) override
	{
		dump("StringAt", expr, " id=", expr->getId());
		indentUp();
		expr->getAtExpression()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::StringInRangeExpression* expr) override
	{
		dump("StringInRange", expr, " id=", expr->getId());
		indentUp();
		expr->getRangeExpression()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::StringCountExpression* expr) override
	{
		dump("StringCount", expr, " id=", expr->getId());
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::StringOffsetExpression* expr) override
	{
		dump("StringOffset", expr, " id=", expr->getId());
		if (auto indexExpression = expr->getIndexExpression())
		{
			indentUp();
			indexExpression->accept(this);
			indentDown();
		}

		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::StringLengthExpression* expr) override
	{
		dump("StringLength", expr, " id=", expr->getId());
		if (auto indexExpression = expr->getIndexExpression())
		{
			indentUp();
			indexExpression->accept(this);
			indentDown();
		}

		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::NotExpression* expr) override
	{
		dump("Not", expr);
		indentUp();
		expr->getOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::UnaryMinusExpression* expr) override
	{
		dump("UnaryMinus", expr);
		indentUp();
		expr->getOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::BitwiseNotExpression* expr) override
	{
		dump("BitwiseNot", expr);
		indentUp();
		expr->getOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::AndExpression* expr) override
	{
		dump("And", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::OrExpression* expr) override
	{
		dump("Or", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::LtExpression* expr) override
	{
		dump("LessThan", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::GtExpression* expr) override
	{
		dump("GreaterThan", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::LeExpression* expr) override
	{
		dump("LessThanOrEqual", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::GeExpression* expr) override
	{
		dump("GreaterThanOrEqual", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::EqExpression* expr) override
	{
		dump("Equal", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::NeqExpression* expr) override
	{
		dump("NotEqual", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ContainsExpression* expr) override
	{
		dump("Contains", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::MatchesExpression* expr) override
	{
		dump("Matches", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::PlusExpression* expr) override
	{
		dump("Plus", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::MinusExpression* expr) override
	{
		dump("Minus", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::MultiplyExpression* expr) override
	{
		dump("Multiply", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::DivideExpression* expr) override
	{
		dump("Divide", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ModuloExpression* expr) override
	{
		dump("Modulo", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::BitwiseXorExpression* expr) override
	{
		dump("BitwiseXor", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::BitwiseAndExpression* expr) override
	{
		dump("BitwiseAnd", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::BitwiseOrExpression* expr) override
	{
		dump("BitwiseOr", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ShiftLeftExpression* expr) override
	{
		dump("ShiftLeft", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ShiftRightExpression* expr) override
	{
		dump("ShiftRight", expr);
		indentUp();
		expr->getLeftOperand()->accept(this);
		expr->getRightOperand()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ForIntExpression* expr) override
	{
		dump("ForInt", expr);
		indentUp();
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
		expr->getBody()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ForStringExpression* expr) override
	{
		dump("ForString", expr);
		indentUp();
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
		expr->getBody()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::OfExpression* expr) override
	{
		dump("Of", expr);
		indentUp();
		expr->getVariable()->accept(this);
		expr->getIteratedSet()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::SetExpression* expr) override
	{
		dump("Set", expr, " size=", expr->getElements().size());
		indentUp();
		for (auto& elem : expr->getElements())
			elem->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::RangeExpression* expr) override
	{
		dump("Range", expr);
		indentUp();
		expr->getLow()->accept(this);
		expr->getHigh()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::IdExpression* expr) override
	{
		dump("Id", expr, " id=", expr->getSymbol()->getName());
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::StructAccessExpression* expr) override
	{
		dump("StructAccess", expr, " id=", expr->getSymbol()->getName());
		indentUp();
		expr->getStructure()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ArrayAccessExpression* expr) override
	{
		dump("ArrayAccess", expr, " id=", expr->getSymbol()->getName());
		indentUp();

		dump("[array]", expr);
		indentUp();
		expr->getArray()->accept(this);
		indentDown();

		dump("[accessor]", expr);
		indentUp();
		expr->getAccessor()->accept(this);
		indentDown();

		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::FunctionCallExpression* expr) override
	{
		dump("FunctionCall", expr, " args_count=", expr->getArguments().size());
		indentUp();

		dump("[symbol]", expr);
		indentUp();
		expr->getFunction()->accept(this);
		indentDown();

		dump("[args]", expr);
		indentUp();
		for (auto& arg : expr->getArguments())
			arg->accept(this);
		indentDown();

		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::BoolLiteralExpression* expr) override
	{
		dump("BoolLiteral", expr, " value=", expr->getText());
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::StringLiteralExpression* expr) override
	{
		dump("StringLiteral", expr, " value=", expr->getText());
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::IntLiteralExpression* expr) override
	{
		dump("IntLiteral", expr, " value=", expr->getText());
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::DoubleLiteralExpression* expr) override
	{
		dump("DoubleLiteral", expr, " value=", expr->getText());
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::FilesizeExpression* expr) override
	{
		dump("Filesize", expr);
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::EntrypointExpression* expr) override
	{
		dump("Entrypoint", expr);
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::AllExpression* expr) override
	{
		dump("All", expr);
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::AnyExpression* expr) override
	{
		dump("Any", expr);
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ThemExpression* expr) override
	{
		dump("Them", expr);
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::ParenthesesExpression* expr) override
	{
		dump("Parentheses", expr);
		indentUp();
		expr->getEnclosedExpression()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::IntFunctionExpression* expr) override
	{
		dump("IntFunction", expr, " function=", expr->getFunction());
		indentUp();
		expr->getArgument()->accept(this);
		indentDown();
		return {};
	}

	virtual yaramod::VisitResult visit(yaramod::RegexpExpression* expr) override
	{
		dump("Regexp", expr, " text=", expr->getRegexpString()->getPureText());
		return {};
	}

private:
	void indentUp() { _indent += 4; }
	void indentDown() { _indent -= 4; }

	template <typename T, typename... Args>
	void dump(const std::string& name, T* expr, Args&&... args)
	{
		std::cout << std::string(_indent, ' ') << name << "[" << expr << "] ";
		dump_helper(args...);
	}

	void dump_helper()
	{
		std::cout << std::endl;
	}

	template <typename T, typename... Args>
	void dump_helper(T&& val, Args&&... args)
	{
		std::cout << val;
		dump_helper(args...);
	}

	std::uint32_t _indent;
};
