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
	virtual yaramod::Visitee::ReturnType visit(yaramod::NotExpression* expr) override
	{
		auto newExpr = expr->getOperand()->accept(this);

		// Negate the value of boolean constant
		auto boolVal = newExpr ? newExpr.value()->getExpression()->as<yaramod::BoolLiteralExpression>() : nullptr;
		if (boolVal)
			return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(!boolVal->getValue());

		return defaultHandler(expr, newExpr);
	}

	virtual yaramod::Visitee::ReturnType visit(yaramod::AndExpression* expr) override
	{
		auto leftExpr = expr->getLeftOperand()->accept(this);
		auto rightExpr = expr->getRightOperand()->accept(this);
		auto leftBool = leftExpr ? leftExpr.value()->getExpression()->as<yaramod::BoolLiteralExpression>() : nullptr;
		auto rightBool = rightExpr ? rightExpr.value()->getExpression()->as<yaramod::BoolLiteralExpression>() : nullptr;

		// If both sides of AND are boolean constants then determine the value based on truth table of AND
		// T and T = T
		// T and F = F
		// F and T = F
		// F and F = F
		if (leftBool && rightBool)
		{
			return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(leftBool->getValue() && rightBool->getValue());
		}
		// Only left-hand side is boolean constant
		else if (leftBool)
		{
			// F and X = F
			if (!leftBool->getValue())
				return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(false);
			// T and X = X
			else
				return expr->getRightOperand();
		}
		// Only right-hand side is boolean constant
		else if (rightBool)
		{
			// X and F = F
			if (!rightBool->getValue())
				return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(false);
			// X and T = X
			else
				return expr->getLeftOperand();
		}

		return defaultHandler(expr, leftExpr, rightExpr);
	}

	virtual yaramod::Visitee::ReturnType visit(yaramod::OrExpression* expr) override
	{
		auto leftExpr = expr->getLeftOperand()->accept(this);
		auto rightExpr = expr->getRightOperand()->accept(this);
		auto leftBool = leftExpr ? leftExpr.value()->getExpression()->as<yaramod::BoolLiteralExpression>() : nullptr;
		auto rightBool = rightExpr ? rightExpr.value()->getExpression()->as<yaramod::BoolLiteralExpression>() : nullptr;

		// If both sides of OR are boolean constants then determine the value based on truth table of OR
		// T or T = T
		// T or F = T
		// F or T = T
		// F or F = F
		if (leftBool && rightBool)
		{
			return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(leftBool->getValue() || rightBool->getValue());
		}
		// Only left-hand side is boolean constant
		else if (leftBool)
		{
			// T or X = T
			if (leftBool->getValue())
				return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(true);
			// F or X = X
			else
				expr->getRightOperand();
		}
		// Only right-hand side is boolean constant
		else if (rightBool)
		{
			// X or T = T
			if (rightBool->getValue())
				return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(true);
			// X or F = X
			else
				return expr->getLeftOperand();
		}

		return defaultHandler(expr, leftExpr, rightExpr);
	}

	virtual yaramod::Visitee::ReturnType visit(yaramod::ParenthesesExpression* expr) override
	{
		auto newExpr = expr->getEnclosedExpression()->accept(this);

		// Remove parentheses around boolean constants and lift their value up
		auto boolVal = newExpr ? newExpr.value()->getExpression()->as<yaramod::BoolLiteralExpression>() : nullptr;
		if (boolVal)
			return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(boolVal->getValue());

		return defaultHandler(expr, newExpr);
	}

	virtual yaramod::Visitee::ReturnType visit(yaramod::BoolLiteralExpression* expr) override
	{
		// Lift up boolean value
		return yaramod::makeASTNode<yaramod::BoolLiteralExpression>(expr->getValue());
	}
};
