/**
 * @file src/parser/yy/parser.y
 * @brief Parser for YARA parser.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

%code requires {
#include <iterator>

#include "yaramod/types/expressions.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/literal.h"
#include "yaramod/types/meta.h"
#include "yaramod/types/plain_string.h"
#include "yaramod/types/regexp.h"
#include "yaramod/types/rule.h"
#include "yaramod/utils/trie.h"

namespace yaramod { class ParserDriver; }

// Uncomment for debugging
// See also other occurrences of 'debugging' in this file and constructor of ParserDriver to enable it
#define YYDEBUG 1
}

%code top {
#include "yaramod/parser/parser_driver.h"

using namespace yaramod;

static yy::Parser::symbol_type yylex(ParserDriver& driver)
{
	return driver.getLexer().getNextToken();
}
}

%skeleton "lalr1.cc"
%require "3.0"

%define api.token.constructor
%define api.value.type variant
%define parse.assert
%locations
%error-verbose

%define api.namespace { yaramod::yy }
%define parser_class_name { Parser }
%parse-param { yaramod::ParserDriver& driver }
%lex-param { yaramod::ParserDriver& driver }

// Uncomment for debugging
// See also other occurrences of 'debugging' in this file and constructor of ParserDriver to enable it
%define parse.trace
%debug

%token END
%token RANGE
%token DOT
%token LT
%token GT
%token LE
%token GE
%token EQ
%token NEQ
%token SHIFT_LEFT
%token SHIFT_RIGHT
%token MINUS
%token PLUS
%token MULTIPLY
%token DIVIDE
%token MODULO
%token BITWISE_XOR
%token BITWISE_AND
%token BITWISE_OR
%token BITWISE_NOT
%token LP
%token RP
%token LCB
%token RCB
%token ASSIGN
%token COLON
%token COMMA
%token PRIVATE
%token GLOBAL
%token RULE
%token META
%token STRINGS
%token CONDITION
%token ASCII
%token NOCASE
%token WIDE
%token FULLWORD
%token BOOL_TRUE
%token BOOL_FALSE
%token IMPORT_MODULE
%token NOT
%token AND
%token OR
%token ALL
%token ANY
%token OF
%token THEM
%token FOR
%token ENTRYPOINT
%token OP_AT
%token OP_IN
%token FILESIZE
%token CONTAINS
%token MATCHES
%token <std::string> SLASH
%token <std::string> STRING_LITERAL INTEGER DOUBLE
%token <std::string> STRING_ID STRING_ID_WILDCARD STRING_LENGTH STRING_OFFSET STRING_COUNT
%token <std::string> ID
%token <std::string> INTEGER_FUNCTION

%token HEX_OR
%token LSQB
%token RSQB
%token HEX_WILDCARD
%token DASH
%token <std::uint8_t> HEX_NIBBLE
%token <std::uint64_t> HEX_INTEGER

%token REGEXP_OR
%token REGEXP_ITER
%token REGEXP_PITER
%token REGEXP_OPTIONAL
%token REGEXP_START_OF_LINE
%token REGEXP_END_OF_LINE
%token REGEXP_ANY_CHAR
%token REGEXP_WORD_CHAR
%token REGEXP_NON_WORD_CHAR
%token REGEXP_SPACE
%token REGEXP_NON_SPACE
%token REGEXP_DIGIT
%token REGEXP_NON_DIGIT
%token REGEXP_WORD_BOUNDARY
%token REGEXP_NON_WORD_BOUNDARY
%token <std::string> REGEXP_CHAR
%token <std::pair<nonstd::optional<std::uint64_t>, nonstd::optional<std::uint64_t>>> REGEXP_RANGE
%token <std::string> REGEXP_CLASS

%type <yaramod::Rule::Modifier> rule_mod
%type <yaramod::Rule> rule
%type <std::vector<yaramod::Meta>> metas metas_body
%type <std::shared_ptr<yaramod::Rule::StringsTrie>> strings strings_body
%type <std::shared_ptr<yaramod::String>> string
%type <std::uint32_t> string_mods
%type <yaramod::Literal> literal
%type <bool> boolean
%type <Expression::Ptr> condition expression primary_expression for_expression integer_set string_set range identifier
%type <std::vector<Expression::Ptr>> integer_enumeration string_enumeration arguments
%type <std::vector<std::string>> tags tag_list

%type <std::vector<std::shared_ptr<yaramod::HexStringUnit>>> hex_string hex_string_edge hex_string_body hex_byte
%type <std::shared_ptr<yaramod::HexStringUnit>> hex_or hex_jump
%type <std::vector<std::shared_ptr<yaramod::HexString>>> hex_or_body

%type <std::shared_ptr<yaramod::String>> regexp regexp_body
%type <std::shared_ptr<yaramod::RegexpUnit>> regexp_or regexp_repeat regexp_single
%type <std::vector<std::shared_ptr<yaramod::RegexpUnit>>> regexp_concat
%type <bool> regexp_greedy

%start rules

%left OR
%left AND
%left BITWISE_OR
%left BITWISE_XOR
%left BITWISE_AND
%left EQ NEQ
%left LT LE GT GE
%left SHIFT_LEFT SHIFT_RIGHT
%left PLUS MINUS
%left MULTIPLY DIVIDE MODULO
%right NOT BITWISE_NOT UNARY_MINUS

/**
 * Expect one shift/reduce conflict. This conflict happens most probably because of these rules
 *
 * expression -> ( expression )
 * expression -> primary_expression
 * primary_expression -> ( primary_expression )
 *
 * When bison parser sees ')', it can't decide whether to shift it
 * and continue with rule primary_expression -> ( primary_expression ),
 * or to reduce primary_expression to expression and then shift ')'.
 * In the end, it produces the same result both ways.
 */
%expect 1

%%

rules
	: rules rule
	| rules import
	| rules END { YYACCEPT; }
	| %empty
	;

import
	: IMPORT_MODULE STRING_LITERAL[module]
		{
			if (!driver._file.addImport($module))
			{
				error(driver.getLocation(), "Unrecognized module '" + $module + "' imported");
				YYABORT;
			}
		}
	;

rule
	: rule_mod RULE
		{
			driver.markStartOfRule();
		}
		ID[id]
		{
			if (driver.ruleExists($id))
			{
				error(driver.getLocation(), "Redefinition of rule '" + $id + "'");
				YYABORT;
			}
		}
		tags LCB metas strings condition RCB
		{
			driver.addRule(Rule(std::move($id), $rule_mod, std::move($metas), std::move($strings), std::move($condition), std::move($tags)));
		}
	;

rule_mod
	: GLOBAL { $$ = Rule::Modifier::Global; }
	| PRIVATE { $$ = Rule::Modifier::Private; }
	| %empty { $$ = Rule::Modifier::None; }
	;

tags
	: COLON tag_list { $$ = std::move($tag_list); }
	| %empty { $$.clear(); }
	;

tag_list
	: tag_list ID
		{
			$$ = std::move($1);
			$$.push_back(std::move($2));
		}
	| ID { $$.push_back(std::move($1)); }
	;

metas
	: META COLON metas_body { $$ = std::move($metas_body); }
	| %empty { $$.clear(); }
	;

metas_body
	: metas_body[body] ID ASSIGN literal
		{
			$$ = std::move($body);
			$$.emplace_back(std::move($2), std::move($4));
		}
	| %empty { $$.clear(); }
	;

strings
	: STRINGS COLON strings_body { $$ = std::move($strings_body); }
	| %empty
		{
			$$ = std::make_shared<Rule::StringsTrie>();
			driver.setCurrentStrings($$);
		}
	;

strings_body
	: strings_body[body] STRING_ID[id] ASSIGN string
		{
			$$ = std::move($body);
			$string->setIdentifier(std::move($id));

			if (!$$->insert($string->getIdentifier(), std::move($string)))
			{
				error(driver.getLocation(), "Redefinition of string '" + $string->getIdentifier() + "'");
				YYABORT;
			}
		}
	| %empty
		{
			$$ = std::make_shared<Rule::StringsTrie>();
			driver.setCurrentStrings($$);
		}
	;

string
	: STRING_LITERAL[literal] string_mods
		{
			$$ = std::make_shared<PlainString>(std::move($literal));
			$$->setModifiers($string_mods);
		}
	| LCB
		{
			driver.getLexer().switchToHexLexer();
		}
		hex_string RCB
		{
			$$ = std::make_shared<HexString>(std::move($hex_string));
			driver.getLexer().switchToYaraLexer();
		}
	| regexp string_mods
		{
			$$ = std::move($regexp);
			$$->setModifiers($string_mods);
		}
	;

condition
	: CONDITION COLON expression { $$ = std::move($expression); }
	;

expression
	: boolean
		{
			$$ = std::make_shared<BoolLiteralExpression>($1);
			$$->setType(Expression::Type::Bool);
		}
	| STRING_ID
		{
			if (!driver.stringExists($1))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1 + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringExpression>(std::move($1));
			$$->setType(Expression::Type::Bool);
		}
	| STRING_ID OP_AT primary_expression
		{
			if (!driver.stringExists($1))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1 + "'");
				YYABORT;
			}

			if (!$primary_expression->isInt())
			{
				error(driver.getLocation(), "operator 'at' expects integer on the right-hand side of the expression");
				YYABORT;
			}

			$$ = std::make_shared<StringAtExpression>(std::move($1), std::move($primary_expression));
			$$->setType(Expression::Type::Bool);
		}
	| STRING_ID OP_IN range
		{
			if (!driver.stringExists($1))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1 + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringInRangeExpression>(std::move($1), std::move($range));
			$$->setType(Expression::Type::Bool);
		}
	| FOR for_expression ID[id]
		{
			auto symbol = std::make_shared<ValueSymbol>($id, Expression::Type::Int);
			if (!driver.addLocalSymbol(symbol))
			{
				error(driver.getLocation(), "Redefinition of identifier '" + $id + "'");
				YYABORT;
			}
		}
		OP_IN integer_set COLON LP expression[expr] RP
		{
			/* Delete $id before we move it to ForIntExpression */
			driver.removeLocalSymbol($id);
			$$ = std::make_shared<ForIntExpression>(std::move($for_expression), std::move($id), std::move($integer_set), std::move($expr));
			$$->setType(Expression::Type::Bool);
		}
	| FOR for_expression OF string_set
		{
			if (driver.isInStringLoop())
			{
				error(driver.getLocation(), "Nesting of for-loop over strings is not allowed");
				YYABORT;
			}

			driver.stringLoopEnter();
		}
		COLON LP expression[expr] RP
		{
			$$ = std::make_shared<ForStringExpression>(std::move($for_expression), std::move($string_set), std::move($expr));
			$$->setType(Expression::Type::Bool);

			driver.stringLoopLeave();
		}
	| for_expression OF string_set
		{
			$$ = std::make_shared<OfExpression>(std::move($for_expression), std::move($string_set));
			$$->setType(Expression::Type::Bool);
		}
	| NOT expression[expr]
		{
			$$ = std::make_shared<NotExpression>(std::move($expr));
			$$->setType(Expression::Type::Bool);
		}
	| expression[left] AND expression[right]
		{
			$$ = std::make_shared<AndExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| expression[left] OR expression[right]
		{
			$$ = std::make_shared<OrExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] LT primary_expression[right]
		{
			$$ = std::make_shared<LtExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] GT primary_expression[right]
		{
			$$ = std::make_shared<GtExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] LE primary_expression[right]
		{
			$$ = std::make_shared<LeExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] GE primary_expression[right]
		{
			$$ = std::make_shared<GeExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] EQ primary_expression[right]
		{
			$$ = std::make_shared<EqExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] NEQ primary_expression[right]
		{
			$$ = std::make_shared<NeqExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] CONTAINS primary_expression[right]
		{
			if (!$left->isString())
			{
				error(driver.getLocation(), "operator 'contains' expects string on the left-hand side of the expression");
				YYABORT;
			}

			if (!$right->isString())
			{
				error(driver.getLocation(), "operator 'contains' expects string on the right-hand side of the expression");
				YYABORT;
			}

			$$ = std::make_shared<ContainsExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] MATCHES regexp[right]
		{
			if (!$left->isString())
			{
				error(driver.getLocation(), "operator 'matches' expects string on the left-hand side of the expression");
				YYABORT;
			}

			auto regexp = std::make_shared<RegexpExpression>(std::move($right));
			$$ = std::make_shared<MatchesExpression>(std::move($left), std::move(regexp));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression
		{
			$$ = std::move($primary_expression);
		}
	| LP expression[expr] RP
		{
			auto type = $expr->getType();
			$$ = std::make_shared<ParenthesesExpression>(std::move($expr));
			$$->setType(type);
		}
	;

primary_expression
	: LP primary_expression[expr] RP
		{
			auto type = $expr->getType();
			$$ = std::make_shared<ParenthesesExpression>(std::move($expr));
			$$->setType(type);
		}
	| FILESIZE
		{
			$$ = std::make_shared<FilesizeExpression>();
			$$->setType(Expression::Type::Int);
		}
	| ENTRYPOINT
		{
			$$ = std::make_shared<EntrypointExpression>();
			$$->setType(Expression::Type::Int);
		}
	| INTEGER
		{
			$$ = std::make_shared<IntLiteralExpression>(std::move($1));
			$$->setType(Expression::Type::Int);
		}
	| DOUBLE
		{
			$$ = std::make_shared<DoubleLiteralExpression>(std::move($1));
			$$->setType(Expression::Type::Float);
		}
	| STRING_LITERAL
		{
			$$ = std::make_shared<StringLiteralExpression>(std::move($1));
			$$->setType(Expression::Type::String);
		}
	| STRING_COUNT
		{
			// Replace '#' for '$' to get string id
			auto stringId = $1;
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1 + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringCountExpression>(std::move($1));
			$$->setType(Expression::Type::Int);
		}
	| STRING_OFFSET
		{
			// Replace '@' for '$' to get string id
			auto stringId = $1;
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1 + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringOffsetExpression>(std::move($1));
			$$->setType(Expression::Type::Int);
		}
	| STRING_OFFSET LSQB primary_expression RSQB
		{
			// Replace '@' for '$' to get string id
			auto stringId = $1;
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1 + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringOffsetExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| STRING_LENGTH
		{
			// Replace '!' for '$' to get string id
			auto stringId = $1;
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1 + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringLengthExpression>(std::move($1));
			$$->setType(Expression::Type::Int);
		}
	| STRING_LENGTH LSQB primary_expression RSQB
		{
			// Replace '!' for '$' to get string id
			auto stringId = $1;
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1 + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringLengthExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| MINUS primary_expression %prec UNARY_MINUS
		{
			if (!$2->isInt() && !$2->isFloat())
			{
				error(driver.getLocation(), "unary minus expects integer or float type");
				YYABORT;
			}

			auto type = $2->getType();
			$$ = std::make_shared<UnaryMinusExpression>(std::move($2));
			$$->setType(type);
		}
	| primary_expression PLUS primary_expression
		{
			if (!$1->isInt() && !$1->isFloat())
			{
				error(driver.getLocation(), "operator '+' expects integer or float on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt() && !$3->isFloat())
			{
				error(driver.getLocation(), "operator '+' expects integer or float on the right-hand side");
				YYABORT;
			}

			auto type = ($1->isInt() && $3->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			$$ = std::make_shared<PlusExpression>(std::move($1), std::move($3));
			$$->setType(type);
		}
	| primary_expression MINUS primary_expression
		{
			if (!$1->isInt() && !$1->isFloat())
			{
				error(driver.getLocation(), "operator '-' expects integer or float on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt() && !$3->isFloat())
			{
				error(driver.getLocation(), "operator '-' expects integer or float on the right-hand side");
				YYABORT;
			}

			auto type = ($1->isInt() && $3->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			$$ = std::make_shared<MinusExpression>(std::move($1), std::move($3));
			$$->setType(type);
		}
	| primary_expression MULTIPLY primary_expression
		{
			if (!$1->isInt() && !$1->isFloat())
			{
				error(driver.getLocation(), "operator '*' expects integer or float on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt() && !$3->isFloat())
			{
				error(driver.getLocation(), "operator '*' expects integer or float on the right-hand side");
				YYABORT;
			}

			auto type = ($1->isInt() && $3->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			$$ = std::make_shared<MultiplyExpression>(std::move($1), std::move($3));
			$$->setType(type);
		}
	| primary_expression DIVIDE primary_expression
		{
			if (!$1->isInt() && !$1->isFloat())
			{
				error(driver.getLocation(), "operator '\\' expects integer or float on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt() && !$3->isFloat())
			{
				error(driver.getLocation(), "operator '\\' expects integer or float on the right-hand side");
				YYABORT;
			}

			auto type = ($1->isInt() && $3->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			$$ = std::make_shared<DivideExpression>(std::move($1), std::move($3));
			$$->setType(type);
		}
	| primary_expression MODULO primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '%' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '%' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<ModuloExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression BITWISE_XOR primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '^' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '^' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<BitwiseXorExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression BITWISE_AND primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '&' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '&' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<BitwiseAndExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression BITWISE_OR primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '|' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '|' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<BitwiseOrExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| BITWISE_NOT primary_expression
		{
			if (!$2->isInt())
			{
				error(driver.getLocation(), "bitwise not expects integer");
				YYABORT;
			}

			$$ = std::make_shared<BitwiseNotExpression>(std::move($2));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression SHIFT_LEFT primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '<<' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '<<' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<ShiftLeftExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression SHIFT_RIGHT primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '>>' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '>>' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<ShiftRightExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| INTEGER_FUNCTION LP primary_expression RP
		{
			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '" + $1 + "' expects integer");
				YYABORT;
			}

			$$ = std::make_shared<IntFunctionExpression>(std::move($1), std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| identifier
		{
			$$ = std::move($identifier);
		}
	| regexp
		{
			$$ = std::make_shared<RegexpExpression>(std::move($regexp));
			$$->setType(Expression::Type::Regexp);
		}
	;

range
	: LP primary_expression[low] RANGE primary_expression[high] RP
		{
			if (!$low->isInt())
			{
				error(driver.getLocation(), "operator '..' expects integer as lower bound of the interval");
				YYABORT;
			}

			if (!$high->isInt())
			{
				error(driver.getLocation(), "operator '..' expects integer as higher bound of the interval");
				YYABORT;
			}

			$$ = std::make_shared<RangeExpression>(std::move($low), std::move($high));
		}
	;

for_expression
	: primary_expression { $$ = std::move($primary_expression); }
	| ALL { $$ = std::make_shared<AllExpression>(); }
	| ANY { $$ = std::make_shared<AnyExpression>(); }
	;

integer_set
	: LP integer_enumeration RP { $$ = std::make_shared<SetExpression>(std::move($integer_enumeration)); }
	| range { $$ = std::move($range); }
	;

integer_enumeration
	: primary_expression[expr]
		{
			if (!$expr->isInt())
			{
				error(driver.getLocation(), "integer set expects integer type");
				YYABORT;
			}

			$$.push_back(std::move($expr));
		}
	| integer_enumeration[enum] COMMA primary_expression[expr]
		{
			if (!$expr->isInt())
			{
				error(driver.getLocation(), "integer set expects integer type");
				YYABORT;
			}

			$$ = std::move($enum);
			$$.push_back(std::move($expr));
		}
	;

string_set
	: LP string_enumeration RP { $$ = std::make_shared<SetExpression>(std::move($string_enumeration)); }
	| THEM { $$ = std::make_shared<ThemExpression>(); }
	;

string_enumeration
	: STRING_ID[id]
		{
			if (!driver.stringExists($id))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $id + "'");
				YYABORT;
			}

			$$.push_back(std::make_shared<StringExpression>(std::move($id)));
		}
	| STRING_ID_WILDCARD[id]
		{
			if (!driver.stringExists($id))
			{
				error(driver.getLocation(), "No string matched with wildcard '" + $id + "'");
				YYABORT;
			}

			$$.push_back(std::make_shared<StringWildcardExpression>(std::move($id)));
		}
	| string_enumeration[enum] COMMA STRING_ID[id]
		{
			if (!driver.stringExists($id))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $id + "'");
				YYABORT;
			}

			$$ = std::move($enum);
			$$.push_back(std::make_shared<StringExpression>(std::move($id)));
		}
	| string_enumeration[enum] COMMA STRING_ID_WILDCARD[id]
		{
			if (!driver.stringExists($id))
			{
				error(driver.getLocation(), "No string matched with wildcard '" + $id + "'");
				YYABORT;
			}

			$$ = std::move($enum);
			$$.push_back(std::make_shared<StringWildcardExpression>(std::move($id)));
		}
	;

identifier
	: ID
		{
			auto symbol = driver.findSymbol($1);
			if (!symbol)
			{
				error(driver.getLocation(), "Unrecognized identifier '" + $1 + "' referenced");
				YYABORT;
			}

			$$ = std::make_shared<IdExpression>(symbol);
			$$->setType(symbol->getDataType());
		}
	| identifier DOT ID
		{
			if (!$1->isObject())
			{
				error(driver.getLocation(), "Identifier '" + $1->getText() + "' is not an object");
				YYABORT;
			}

			auto parentSymbol = std::static_pointer_cast<const IdExpression>($1)->getSymbol();
			if (!parentSymbol->isStructure())
			{
				error(driver.getLocation(), "Identifier '" + parentSymbol->getName() + "' is not a structure");
				YYABORT;
			}

			auto structParentSymbol = std::static_pointer_cast<const StructureSymbol>(parentSymbol);
			auto attr = structParentSymbol->getAttribute($3);
			if (!attr)
			{
				error(driver.getLocation(), "Unrecognized identifier '" + $3 + "' referenced");
				YYABORT;
			}

			auto symbol = attr.value();
			$$ = std::make_shared<StructAccessExpression>(symbol, std::move($1));
			$$->setType(symbol->getDataType());
		}
	| identifier LSQB primary_expression RSQB
		{
			if (!$1->isObject())
			{
				error(driver.getLocation(), "Identifier '" + $1->getText() + "' is not an object");
				YYABORT;
			}

			auto parentSymbol = std::static_pointer_cast<const IdExpression>($1)->getSymbol();
			if (!parentSymbol->isArray() && !parentSymbol->isDictionary())
			{
				error(driver.getLocation(), "Identifier '" + parentSymbol->getName() + "' is not an array nor dictionary");
				YYABORT;
			}

			auto iterParentSymbol = std::static_pointer_cast<const IterableSymbol>(parentSymbol);
			$$ = std::make_shared<ArrayAccessExpression>(iterParentSymbol->getStructuredElementType(), std::move($1), std::move($primary_expression));
			$$->setType(iterParentSymbol->getElementType());
		}
	| identifier LP arguments RP
		{
			if (!$1->isObject())
			{
				error(driver.getLocation(), "Identifier '" + $1->getText() + "' is not an object");
				YYABORT;
			}

			auto parentSymbol = std::static_pointer_cast<const IdExpression>($1)->getSymbol();
			if (!parentSymbol->isFunction())
			{
				error(driver.getLocation(), "Identifier '" + parentSymbol->getName() + "' is not a function");
				YYABORT;
			}

			auto funcParentSymbol = std::static_pointer_cast<const FunctionSymbol>(parentSymbol);

			// Make copy of just argument types because symbols are not aware of expressions
			std::vector<Expression::Type> argTypes;
			std::for_each($arguments.begin(), $arguments.end(),
				[&argTypes](const Expression::Ptr& expr)
				{
					argTypes.push_back(expr->getType());
				});

			if (!funcParentSymbol->overloadExists(argTypes))
			{
				error(driver.getLocation(), "No matching overload of function '" + funcParentSymbol->getName() + "' for these types of parameters");
				YYABORT;
			}

			$$ = std::make_shared<FunctionCallExpression>(std::move($1), std::move($arguments));
			$$->setType(funcParentSymbol->getReturnType());
		}
	;

arguments
	: arguments COMMA expression
		{
			$$ = std::move($1);
			$$.push_back(std::move($expression));
		}
	| expression { $$.push_back(std::move($expression)); }
	| %empty { $$.clear(); }
	;

string_mods
	: string_mods ASCII { $$ = $1 | String::Modifiers::Ascii; }
	| string_mods WIDE { $$ = $1 | String::Modifiers::Wide; }
	| string_mods NOCASE { $$ = $1 | String::Modifiers::Nocase; }
	| string_mods FULLWORD { $$ = $1 | String::Modifiers::Fullword; }
	| %empty { $$ = String::Modifiers::None; }
	;

literal
	: STRING_LITERAL { $$ = Literal(std::move($1), Literal::Type::String); }
	| INTEGER { $$ = Literal(std::move($1), Literal::Type::Int); }
	| boolean { $$ = Literal($1); }
	;

boolean
	: BOOL_TRUE { $$ = true; }
	| BOOL_FALSE { $$ = false; }
	;

hex_string
	: hex_string_edge { $$ = std::move($hex_string_edge); }
	| hex_string_edge hex_string_body hex_string_edge
		{
			$$ = std::move($1);
			$$.reserve($$.size() + $2.size() + $3.size());
			std::move($2.begin(), $2.end(), std::back_inserter($$));
			std::move($3.begin(), $3.end(), std::back_inserter($$));
		}

hex_string_edge
	: hex_byte { $$ = std::move($hex_byte); }
	| hex_or { $$.push_back(std::move($hex_or)); }
	;

hex_byte
	: HEX_NIBBLE HEX_NIBBLE
		{
			auto first = std::make_shared<HexStringNibble>($1);
			auto second = std::make_shared<HexStringNibble>($2);
			$$.reserve(2);
			$$.push_back(std::move(first));
			$$.push_back(std::move(second));
		}
	| HEX_NIBBLE HEX_WILDCARD
		{
			auto first = std::make_shared<HexStringNibble>($1);
			auto second = std::make_shared<HexStringWildcard>();
			$$.reserve(2);
			$$.push_back(std::move(first));
			$$.push_back(std::move(second));
		}
	| HEX_WILDCARD HEX_NIBBLE
		{
			auto first = std::make_shared<HexStringWildcard>();
			auto second = std::make_shared<HexStringNibble>($2);
			$$.reserve(2);
			$$.push_back(std::move(first));
			$$.push_back(std::move(second));
		}
	| HEX_WILDCARD HEX_WILDCARD
		{
			auto first = std::make_shared<HexStringWildcard>();
			auto second = std::make_shared<HexStringWildcard>();
			$$.reserve(2);
			$$.push_back(std::move(first));
			$$.push_back(std::move(second));
		}
	;

hex_string_body
	: hex_string_body[body] hex_byte
		{
			$$ = std::move($body);
			std::move($hex_byte.begin(), $hex_byte.end(), std::back_inserter($$));
		}
	| hex_string_body[body] hex_or
		{
			$$ = std::move($body);
			$$.push_back(std::move($hex_or));
		}
	| hex_string_body[body] hex_jump
		{
			$$ = std::move($body);
			$$.push_back(std::move($hex_jump));
		}
	| %empty { $$.clear(); }
	;

hex_or
	: LP hex_or_body RP { $$ = std::make_shared<HexStringOr>(std::move($hex_or_body)); }

hex_or_body
	: hex_string_body
		{
			auto hexStr = std::make_shared<HexString>(std::move($hex_string_body));
			$$.push_back(std::move(hexStr));
		}
	| hex_or_body[body] HEX_OR hex_string_body
		{
			$$ = std::move($body);
			auto hexStr = std::make_shared<HexString>(std::move($hex_string_body));
			$$.push_back(std::move(hexStr));
		}
	;

hex_jump
	: LSQB HEX_INTEGER[value] RSQB { $$ = std::make_shared<HexStringJump>($value, $value); }
	| LSQB HEX_INTEGER[low] DASH HEX_INTEGER[high] RSQB { $$ = std::make_shared<HexStringJump>($low, $high); }
	| LSQB HEX_INTEGER[low] DASH RSQB { $$ = std::make_shared<HexStringJump>($low); }
	| LSQB DASH RSQB { $$ = std::make_shared<HexStringJump>(); }
	;

regexp
	: SLASH
		{
			driver.getLexer().switchToRegexpLexer();
		}
		regexp_body SLASH[suffix_mods]
		{
			$$ = std::move($regexp_body);
			std::static_pointer_cast<Regexp>($$)->setSuffixModifiers($suffix_mods);
			driver.getLexer().switchToYaraLexer();
		}

regexp_body
	: regexp_or { $$ = std::make_shared<Regexp>(std::move($regexp_or)); }
	;

regexp_or
	: regexp_concat { $$ = std::make_shared<RegexpConcat>(std::move($regexp_concat)); }
	| regexp_or REGEXP_OR regexp_concat
		{
			auto concat = std::make_shared<RegexpConcat>(std::move($regexp_concat));
			$$ = std::make_shared<RegexpOr>(std::move($1), std::move(concat));
		}
	;

regexp_concat
	: regexp_repeat { $$.push_back(std::move($1)); }
	| regexp_concat regexp_repeat
		{
			$$ = std::move($1);
			$$.push_back(std::move($2));
		}
	;

regexp_repeat
	: regexp_single REGEXP_ITER regexp_greedy { $$ = std::make_shared<RegexpIteration>(std::move($regexp_single), $regexp_greedy); }
	| regexp_single REGEXP_PITER regexp_greedy { $$ = std::make_shared<RegexpPositiveIteration>(std::move($regexp_single), $regexp_greedy); }
	| regexp_single REGEXP_OPTIONAL regexp_greedy { $$ = std::make_shared<RegexpOptional>(std::move($regexp_single), $regexp_greedy); }
	| regexp_single REGEXP_RANGE regexp_greedy
		{
			if (!$2.first && !$2.second)
			{
				error(driver.getLocation(), "Range in regular expression does not have defined lower bound nor higher bound");
				YYABORT;
			}

			if ($2.first && $2.second && $2.first.value() > $2.second.value())
			{
				error(driver.getLocation(), "Range in regular expression has greater lower bound than higher bound");
				YYABORT;
			}

			$$ = std::make_shared<RegexpRange>(std::move($regexp_single), std::move($2), $regexp_greedy);
		}
	| regexp_single { $$ = std::move($regexp_single); }
	| REGEXP_WORD_BOUNDARY { $$ = std::make_shared<RegexpWordBoundary>(); }
	| REGEXP_NON_WORD_BOUNDARY { $$ = std::make_shared<RegexpNonWordBoundary>(); }
	| REGEXP_START_OF_LINE { $$ = std::make_shared<RegexpStartOfLine>(); }
	| REGEXP_END_OF_LINE { $$ = std::make_shared<RegexpEndOfLine>(); }
	;

regexp_greedy
	: %empty { $$ = true; }
	| REGEXP_OPTIONAL { $$ = false; }
	;

regexp_single
	: LP regexp_or RP { $$ = std::make_shared<RegexpGroup>(std::move($2)); }
	| REGEXP_ANY_CHAR { $$ = std::make_shared<RegexpAnyChar>(); }
	| REGEXP_CHAR { $$ = std::make_shared<RegexpText>(std::move($1)); }
	| REGEXP_WORD_CHAR { $$ = std::make_shared<RegexpWordChar>(); }
	| REGEXP_NON_WORD_CHAR { $$ = std::make_shared<RegexpNonWordChar>(); }
	| REGEXP_SPACE { $$ = std::make_shared<RegexpSpace>(); }
	| REGEXP_NON_SPACE { $$ = std::make_shared<RegexpNonSpace>(); }
	| REGEXP_DIGIT { $$ = std::make_shared<RegexpDigit>(); }
	| REGEXP_NON_DIGIT { $$ = std::make_shared<RegexpNonDigit>(); }
	| REGEXP_CLASS[c]
		{
			// It is negative class
			if ($c[0] == '^')
				$$ = std::make_shared<RegexpClass>($c.substr(1, $c.length() - 1), true);
			else
				$$ = std::make_shared<RegexpClass>(std::move($c), false);
		}
	;

%%

// Bison expects implementation of error method by us
void yy::Parser::error(const yy::location& loc, const std::string& message)
{
	std::ostringstream os;
	os << "Error at " << loc << ": " << message;
	throw ParserError(os.str());
}
