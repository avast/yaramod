/**
 * @file src/types/expressions.cpp
 * @brief Implementation of all Expression subclasses.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "yaramod/types/expressions.h"
#include "yaramod/utils/modifying_visitor.h"

namespace yaramod {

VisitResult StringExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StringWildcardExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult StringWildcardExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StringWildcardExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult StringAtExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StringAtExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult StringInRangeExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StringInRangeExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult StringCountExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StringCountExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult StringOffsetExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StringOffsetExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult StringLengthExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StringLengthExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

// VisitResult UnaryOpExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
// {
// 	std::cout << "aaaaaaaa::acceptModifyingVisitor called" << std::endl;	
// 	return v->visit(this);
// }

VisitResult NotExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "NotExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult UnaryMinusExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "UnaryMinusExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult BitwiseNotExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "BitwiseNotExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

// VisitResult BinaryOpExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
// {
// 	std::cout << "aaaaaaaa::acceptModifyingVisitor called" << std::endl;	
// 	return v->visit(this);
// }

VisitResult AndExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "AndExpression::acceptModifyingVisitor called" << std::endl;
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult OrExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "OrExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult LtExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "LtExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult GtExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "GtExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult LeExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "LeExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult GeExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "GeExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult EqExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "EqExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult NeqExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "NeqExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult ContainsExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ContainsExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult MatchesExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "MatchesExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult PlusExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "PlusExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult MinusExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "MinusExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult MultiplyExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "MultiplyExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult DivideExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "DivideExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult ModuloExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ModuloExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult BitwiseXorExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "BitwiseXorExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult BitwiseAndExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "BitwiseAndExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult BitwiseOrExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "BitwiseOrExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult ShiftLeftExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ShiftLeftExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult ShiftRightExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ShiftRightExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

// VisitResult ForExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
// {
// 	std::cout << "aaaaaaaa::acceptModifyingVisitor called" << std::endl;	
// 	return v->visit(this);
// }

VisitResult ForIntExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ForIntExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult ForStringExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ForStringExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult OfExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "OfExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult SetExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "SetExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult RangeExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "RangeExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult IdExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "IdExpression::acceptModifyingVisitor called"  << getText() << std::endl;	
	return v->visit(this);
}

VisitResult StructAccessExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StructAccessExpression::acceptModifyingVisitor called" << getText() << std::endl;	
	return v->visit(this);
}

VisitResult ArrayAccessExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ArrayAccessExpression::acceptModifyingVisitor called" << getText()  << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult FunctionCallExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "FunctionCallExpression::acceptModifyingVisitor called" << getText()  << std::endl;	
	return v->visit(this);
}

// VisitResult LiteralExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
// {
// 	std::cout << "LiteralExpression::acceptModifyingVisitor called" << std::endl;	
// 	return v->visit(this);
// }

VisitResult BoolLiteralExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
	// return result_exp;


	// std::cout << "Puvodni TS: '" << *_tokenStream << "'" << std::endl;
	// TokenIt firstOld = getFirstTokenIt();
	// TokenIt lastOld = std::next(getLastTokenIt());
	// VisitResult output = v->visit(this);
	// Expression* output_exp;
	// try
	// {
	// 	output_exp = std::get<std::shared_ptr<Expression>>(output).get();
	// }
	// catch (std::bad_variant_access& err)
	// {
	// 	throw VisitorResultAccessError(err.what());
	// }
	// std::cout << "TS expr before: '" << *(output_exp->getTokenStream()) << "'" << std::endl;
	// TokenIt firstNew = output_exp->getFirstTokenIt();
	// TokenIt lastNew = std::next(output_exp->getLastTokenIt());
	// _tokenStream->erase(firstOld, lastOld);
	// _tokenStream->move_append(lastOld, output_exp->getTokenStream(), firstNew, lastNew);
	// std::cout << "TS expr after: '" << *(output_exp->getTokenStream()) << "'" << std::endl;
	// std::cout << "Puvodni TS after: '" << *_tokenStream << "'" << std::endl;
	// output_exp->setTokenStream(_tokenStream);
	// return output;
}

VisitResult StringLiteralExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "StringLiteralExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult IntLiteralExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "IntLiteralExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult DoubleLiteralExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "DoubleLiteralExpression::acceptModifyingVisitor" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

// VisitResult KeywordExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
// {
// 	std::cout << "KeywordExpression::acceptModifyingVisitor called" << std::endl;	
// 	return v->visit(this);
// }

//TODO: use it in Base not following 5 derived

VisitResult FilesizeExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "FilesizeExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult EntrypointExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "EntrypointExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult AllExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "AllExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult AnyExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "AnyExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult ThemExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ThemExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult ParenthesesExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "ParenthesesExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult IntFunctionExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "IntFunctionExpression::acceptModifyingVisitor called" << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}

VisitResult RegexpExpression::acceptModifyingVisitor(ModifyingVisitor* v) 
{
	std::cout << "RegexpExpression::acceptModifyingVisitor called with " << getText() << std::endl;	
	TokenIt from = getFirstTokenIt();
	TokenIt to = std::next(getLastTokenIt());
	VisitResult result = v->visit(this);
	extractTokens(result, from, to);
	return result;
}


} //namespace yaramod
