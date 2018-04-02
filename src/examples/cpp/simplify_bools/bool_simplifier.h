/**
 * @file src/examples/simplify_bools/bool_simplifier.h
 * @brief Implementation of boolean simplifier.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <yaramod/utils/modifying_visitor.h>

class BoolSimplifier : public yaramod::ModifyingVisitor
{
public:
	virtual yaramod::VisitResult visit(yaramod::AndExpression* expr) override
	{
		auto retLeft = expr->getLeftOperand()->accept(this);
		auto retRight = expr->getRightOperand()->accept(this);

		yaramod::BoolLiteralExpression* leftBool = nullptr;
		if (auto leftExpr = mpark::get_if<yaramod::Expression::Ptr>(&retLeft))
		{
			if (*leftExpr)
				leftBool = (*leftExpr)->as<yaramod::BoolLiteralExpression>();
		}

		yaramod::BoolLiteralExpression* rightBool = nullptr;
		if (auto rightExpr = mpark::get_if<yaramod::Expression::Ptr>(&retRight))
		{
			if (*rightExpr)
				rightBool = (*rightExpr)->as<yaramod::BoolLiteralExpression>();
		}

		// If both sides of AND are boolean constants then determine the value based on truth table of AND
		// T and T = T
		// T and F = F
		// F and T = F
		// F and F = F
		if (leftBool && rightBool)
		{
			return std::make_shared<yaramod::BoolLiteralExpression>(leftBool->getValue() && rightBool->getValue());
		}
		// Only left-hand side is boolean constant
		else if (leftBool)
		{
			// F and X = F
			if (!leftBool->getValue())
				return std::make_shared<yaramod::BoolLiteralExpression>(false);
			// T and X = X
			else
				return expr->getRightOperand();
		}
		// Only right-hand side is boolean constant
		else if (rightBool)
		{
			// X and F = F
			if (!rightBool->getValue())
				return std::make_shared<yaramod::BoolLiteralExpression>(false);
			// X and T = X
			else
				return expr->getLeftOperand();
		}

		return defaultHandler(expr, retLeft, retRight);
	}

	virtual yaramod::VisitResult visit(yaramod::OrExpression* expr) override
	{
		auto retLeft = expr->getLeftOperand()->accept(this);
		auto retRight = expr->getRightOperand()->accept(this);

		yaramod::BoolLiteralExpression* leftBool = nullptr;
		if (auto leftExpr = mpark::get_if<yaramod::Expression::Ptr>(&retLeft))
		{
			if (*leftExpr)
				leftBool = (*leftExpr)->as<yaramod::BoolLiteralExpression>();
		}

		yaramod::BoolLiteralExpression* rightBool = nullptr;
		if (auto rightExpr = mpark::get_if<yaramod::Expression::Ptr>(&retRight))
		{
			if (*rightExpr)
				rightBool = (*rightExpr)->as<yaramod::BoolLiteralExpression>();
		}

		// If both sides of OR are boolean constants then determine the value based on truth table of OR
		// T or T = T
		// T or F = T
		// F or T = T
		// F or F = F
		if (leftBool && rightBool)
		{
			return std::make_shared<yaramod::BoolLiteralExpression>(leftBool->getValue() || rightBool->getValue());
		}
		// Only left-hand side is boolean constant
		else if (leftBool)
		{
			// T or X = T
			if (leftBool->getValue())
				return std::make_shared<yaramod::BoolLiteralExpression>(true);
			// F or X = X
			else
				expr->getRightOperand();
		}
		// Only right-hand side is boolean constant
		else if (rightBool)
		{
			// X or T = T
			if (rightBool->getValue())
				return std::make_shared<yaramod::BoolLiteralExpression>(true);
			// X or F = X
			else
				return expr->getLeftOperand();
		}

		return defaultHandler(expr, retLeft, retRight);
	}

	virtual yaramod::VisitResult visit(yaramod::NotExpression* expr) override
	{
		auto ret = expr->getOperand()->accept(this);

		// Negate the value of boolean constant
		if (auto newExpr = mpark::get_if<yaramod::Expression::Ptr>(&ret))
		{
			auto boolVal = *newExpr ? (*newExpr)->as<yaramod::BoolLiteralExpression>() : nullptr;
			if (boolVal)
				return std::make_shared<yaramod::BoolLiteralExpression>(!boolVal->getValue());
		}

		return defaultHandler(expr, ret);
	}

	virtual yaramod::VisitResult visit(yaramod::ParenthesesExpression* expr) override
	{
		auto ret = expr->getEnclosedExpression()->accept(this);

		// Remove parentheses around boolean constants and lift their value up
		if (auto newExpr = mpark::get_if<yaramod::Expression::Ptr>(&ret))
		{
			auto boolVal = *newExpr ? (*newExpr)->as<yaramod::BoolLiteralExpression>() : nullptr;
			if (boolVal)
				return std::make_shared<yaramod::BoolLiteralExpression>(boolVal->getValue());
		}

		return defaultHandler(expr, ret);
	}

	virtual yaramod::VisitResult visit(yaramod::BoolLiteralExpression* expr) override
	{
		// Lift up boolean value
		return std::make_shared<yaramod::BoolLiteralExpression>(expr->getValue());
	}
};
