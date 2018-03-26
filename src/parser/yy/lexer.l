/**
 * @file src/parser/yy/lexer.l
 * @brief Lexer for YARA parser.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

%{
#include <cctype>

#include "yaramod/parser/lexer.h"
#include "yaramod/parser/parser_driver.h"
#include "yaramod/utils/utils.h"

using namespace yaramod::yy;

// There is no unistd.h on Windows when building with MSVC.
#ifdef _MSC_VER
	#define YY_NO_UNISTD_H
#endif

#define yyterminate() Parser::make_END(CURRENT_LOC)

#define YY_DECL yaramod::yy::Parser::symbol_type yaramod::yy::Lexer::getNextToken()

#define YY_USER_ACTION _driver.moveLocation(yyleng);
#define CURRENT_LOC _driver.getLocation()
%}

digit       [0-9]
hexdigit    [0-9a-fA-F]
letter      [a-zA-Z]
newline     \n
whitespace  [ \v\r\t]

%option debug
%option noyywrap
%option nodefault
%option yylineno
%option stack
%option c++
%option yyclass="yaramod::yy::Lexer"

%x INCLUDE
%x INCLUDE_FILE
%x MULTILINE_COMMENT
%x STR
%x HEXSTR
%x HEXSTR_JUMP
%x HEXSTR_MULTILINE_COMMENT
%x REGEXP
%x REGEXP_CLASS

%%

".."         { return Parser::make_RANGE(CURRENT_LOC); }
"."          { return Parser::make_DOT(CURRENT_LOC); }
"<"          { return Parser::make_LT(CURRENT_LOC); }
">"          { return Parser::make_GT(CURRENT_LOC); }
"<="         { return Parser::make_LE(CURRENT_LOC); }
">="         { return Parser::make_GE(CURRENT_LOC); }
"=="         { return Parser::make_EQ(CURRENT_LOC); }
"!="         { return Parser::make_NEQ(CURRENT_LOC); }
"<<"         { return Parser::make_SHIFT_LEFT(CURRENT_LOC); }
">>"         { return Parser::make_SHIFT_RIGHT(CURRENT_LOC); }
"-"          { return Parser::make_MINUS(CURRENT_LOC); }
"+"          { return Parser::make_PLUS(CURRENT_LOC); }
"*"          { return Parser::make_MULTIPLY(CURRENT_LOC); }
"\\"         { return Parser::make_DIVIDE(CURRENT_LOC); }
"%"          { return Parser::make_MODULO(CURRENT_LOC); }
"^"          { return Parser::make_BITWISE_XOR(CURRENT_LOC); }
"&"          { return Parser::make_BITWISE_AND(CURRENT_LOC); }
"|"          { return Parser::make_BITWISE_OR(CURRENT_LOC); }
"~"          { return Parser::make_BITWISE_NOT(CURRENT_LOC); }
"("          { return Parser::make_LP(CURRENT_LOC); }
")"          { return Parser::make_RP(CURRENT_LOC); }
"{"          { return Parser::make_LCB(CURRENT_LOC); }
"}"          { return Parser::make_RCB(CURRENT_LOC); }
"["          { return Parser::make_LSQB(CURRENT_LOC); }
"]"          { return Parser::make_RSQB(CURRENT_LOC); }
"="          { return Parser::make_ASSIGN(CURRENT_LOC); }
":"          { return Parser::make_COLON(CURRENT_LOC); }
","          { return Parser::make_COMMA(CURRENT_LOC); }
"/"          { return Parser::make_SLASH(std::string(), CURRENT_LOC); }
"global"     { return Parser::make_GLOBAL(CURRENT_LOC); }
"private"    { return Parser::make_PRIVATE(CURRENT_LOC); }
"rule"       { return Parser::make_RULE(CURRENT_LOC); }
"meta"       { return Parser::make_META(CURRENT_LOC); }
"strings"    { return Parser::make_STRINGS(CURRENT_LOC); }
"condition"  { return Parser::make_CONDITION(CURRENT_LOC); }
"ascii"      { return Parser::make_ASCII(CURRENT_LOC); }
"nocase"     { return Parser::make_NOCASE(CURRENT_LOC); }
"wide"       { return Parser::make_WIDE(CURRENT_LOC); }
"fullword"   { return Parser::make_FULLWORD(CURRENT_LOC); }
"true"       { return Parser::make_BOOL_TRUE(CURRENT_LOC); }
"false"      { return Parser::make_BOOL_FALSE(CURRENT_LOC); }
"import"     { return Parser::make_IMPORT_MODULE(CURRENT_LOC); }
"not"        { return Parser::make_NOT(CURRENT_LOC); }
"and"        { return Parser::make_AND(CURRENT_LOC); }
"or"         { return Parser::make_OR(CURRENT_LOC); }
"all"        { return Parser::make_ALL(CURRENT_LOC); }
"any"        { return Parser::make_ANY(CURRENT_LOC); }
"of"         { return Parser::make_OF(CURRENT_LOC); }
"them"       { return Parser::make_THEM(CURRENT_LOC); }
"for"        { return Parser::make_FOR(CURRENT_LOC); }
"entrypoint" { return Parser::make_ENTRYPOINT(CURRENT_LOC); }
"at"         { return Parser::make_OP_AT(CURRENT_LOC); }
"in"         { return Parser::make_OP_IN(CURRENT_LOC); }
"filesize"   { return Parser::make_FILESIZE(CURRENT_LOC); }
"contains"   { return Parser::make_CONTAINS(CURRENT_LOC); }
"matches"    { return Parser::make_MATCHES(CURRENT_LOC); }
"include"    { BEGIN(INCLUDE); }

<INCLUDE>{newline}           { }
<INCLUDE>{whitespace}*       { }
<INCLUDE>"\""                { BEGIN(INCLUDE_FILE); }
<INCLUDE>.                   { return yyterminate(); }
<INCLUDE_FILE>[^"]+"\""      {
	std::string filePath = std::string(yytext, yyleng - 1);
	if (!_driver.includeFile(filePath))
	{
		_driver.getParser().error(_driver.getLocation(), "Unable to include file '" + filePath + "'");
		return yyterminate();
	}

	BEGIN(INITIAL);
}

"/*"                         { BEGIN(MULTILINE_COMMENT); }
<MULTILINE_COMMENT>"*/"      { BEGIN(INITIAL); }
<MULTILINE_COMMENT>{newline} { _driver.moveLineLocation(); }
<MULTILINE_COMMENT>.         { }

"//"[^\n]*                { }

"\""                      { BEGIN(STR); _strLiteral.clear(); }
<STR>\\t                  { _strLiteral += '\t'; }
<STR>\\n                  { _strLiteral += '\n'; }
<STR>\\x{hexdigit}{2}     {
	std::uint64_t num = 0;
	strToNum(std::string(yytext + 2, yyleng - 2), num, std::hex);
	_strLiteral += static_cast<char>(num);
}
<STR>\\\"                 { _strLiteral += '\"'; }
<STR>\\\\                 { _strLiteral += '\\'; }
<STR>\\.                  {
	_driver.getParser().error(_driver.getLocation(), "Unknown escape sequence \'" + std::string(yytext, yyleng) + "\'");
	return yyterminate();
}
<STR>([^\\"])+            { _strLiteral.append(std::string(yytext, yyleng)); }
<STR>\"                   {
	BEGIN(INITIAL);
	return Parser::make_STRING_LITERAL(_strLiteral, CURRENT_LOC);
}

u?int(8|16|32)(be)?                { return Parser::make_INTEGER_FUNCTION(std::string(yytext, yyleng), CURRENT_LOC); }
"$"({letter}|{digit}|_)*           { return Parser::make_STRING_ID(std::string(yytext, yyleng), CURRENT_LOC); }
"$"({letter}|{digit}|_)*"*"        { return Parser::make_STRING_ID_WILDCARD(std::string(yytext, yyleng), CURRENT_LOC); }
"#"({letter}|{digit}|_)*           { return Parser::make_STRING_COUNT(std::string(yytext, yyleng), CURRENT_LOC); }
"@"({letter}|{digit}|_)*           { return Parser::make_STRING_OFFSET(std::string(yytext, yyleng), CURRENT_LOC); }
"!"({letter}|{digit}|_)*           { return Parser::make_STRING_LENGTH(std::string(yytext, yyleng), CURRENT_LOC); }
({letter}|_)({letter}|{digit}|_)*  { return Parser::make_ID(std::string(yytext, yyleng), CURRENT_LOC); }

"0x"({hexdigit}+)                  { return Parser::make_INTEGER(std::string(yytext, yyleng), CURRENT_LOC); }
{digit}+"."{digit}+                { return Parser::make_DOUBLE(std::string(yytext, yyleng), CURRENT_LOC); }
{digit}+(KB|MB)?                   { return Parser::make_INTEGER(std::string(yytext, yyleng), CURRENT_LOC); }

<HEXSTR>"|"                        { return Parser::make_HEX_OR(CURRENT_LOC); }
<HEXSTR>"("                        { return Parser::make_LP(CURRENT_LOC); }
<HEXSTR>")"                        { return Parser::make_RP(CURRENT_LOC); }
<HEXSTR>"?"                        { return Parser::make_HEX_WILDCARD(CURRENT_LOC); }
<HEXSTR>"}"                        { BEGIN(INITIAL); return Parser::make_RCB(CURRENT_LOC); }
<HEXSTR>{hexdigit}                 {
	unsigned char firstChar = yytext[0];
	std::uint8_t nibble =
		'A' <= std::toupper(firstChar) && std::toupper(firstChar) <= 'F'
		? std::toupper(firstChar) - 'A' + 10
		: firstChar - '0';
	return Parser::make_HEX_NIBBLE(nibble, CURRENT_LOC);
}
<HEXSTR>"["                        { BEGIN(HEXSTR_JUMP); return Parser::make_LSQB(CURRENT_LOC); }
<HEXSTR_JUMP>{digit}*              {
	std::string numStr = std::string(yytext, yyleng);
	std::uint64_t num = 0;
	strToNum(numStr, num, std::dec);
	return Parser::make_HEX_INTEGER(num, CURRENT_LOC);
}
<HEXSTR_JUMP>"-"                   { return Parser::make_DASH(CURRENT_LOC); }
<HEXSTR_JUMP>"]"                   { BEGIN(HEXSTR); return Parser::make_RSQB(CURRENT_LOC); }
<HEXSTR,HEXSTR_JUMP>"//"[^\n]*     { }
<HEXSTR,HEXSTR_JUMP>"/*"           { BEGIN(HEXSTR_MULTILINE_COMMENT); }
<HEXSTR_MULTILINE_COMMENT>"*/"     { BEGIN(HEXSTR); }
<HEXSTR_MULTILINE_COMMENT>.        { }
<HEXSTR,HEXSTR_JUMP>{whitespace}*  { }
<HEXSTR,HEXSTR_JUMP>.              { return yyterminate(); }
<HEXSTR,HEXSTR_JUMP><<EOF>>        { return yyterminate(); }

<REGEXP>"/"i?s?                    { return Parser::make_SLASH(std::string(yytext + 1, yyleng - 1), CURRENT_LOC); }
<REGEXP>"("                        { return Parser::make_LP(CURRENT_LOC); }
<REGEXP>")"                        { return Parser::make_RP(CURRENT_LOC); }
<REGEXP>"|"                        { return Parser::make_REGEXP_OR(CURRENT_LOC); }
<REGEXP>"*"                        { return Parser::make_REGEXP_ITER(CURRENT_LOC); }
<REGEXP>"+"                        { return Parser::make_REGEXP_PITER(CURRENT_LOC); }
<REGEXP>"?"                        { return Parser::make_REGEXP_OPTIONAL(CURRENT_LOC); }
<REGEXP>"^"                        { return Parser::make_REGEXP_START_OF_LINE(CURRENT_LOC); }
<REGEXP>"$"                        { return Parser::make_REGEXP_END_OF_LINE(CURRENT_LOC); }
<REGEXP>"."                        { return Parser::make_REGEXP_ANY_CHAR(CURRENT_LOC); }
<REGEXP>"{"{digit}*,{digit}*"}"    {
	std::string rangeStr = std::string(yytext, yyleng);
	std::string lowStr = rangeStr.substr(1, rangeStr.find(',') - 1);
	std::string highStr = rangeStr.substr(rangeStr.find(',') + 1);
	highStr.pop_back(); // Remove '}' at the end

	std::uint64_t lowNum = 0;
	nonstd::optional<std::uint64_t> low;
	if (strToNum(lowStr, lowNum, std::dec))
		low = lowNum;

	std::uint64_t highNum = 0;
	nonstd::optional<std::uint64_t> high;
	if (strToNum(highStr, highNum, std::dec))
		high = highNum;

	return Parser::make_REGEXP_RANGE(std::make_pair(low, high), CURRENT_LOC);
}
<REGEXP>"{"{digit}+"}"             {
	std::string numStr = std::string(yytext + 1, yyleng - 2);

	nonstd::optional<std::uint64_t> range;
	std::uint64_t num = 0;
	if (strToNum(numStr, num, std::dec))
		range = num;

	return Parser::make_REGEXP_RANGE(std::make_pair(range, range), CURRENT_LOC);
}
<REGEXP>[^\\\[\(\)\|\$\.\^\+\+*\?] { return Parser::make_REGEXP_CHAR(std::string(1, yytext[0]), CURRENT_LOC); }
<REGEXP>"\\w"                      { return Parser::make_REGEXP_WORD_CHAR(CURRENT_LOC); }
<REGEXP>"\\W"                      { return Parser::make_REGEXP_NON_WORD_CHAR(CURRENT_LOC); }
<REGEXP>"\\s"                      { return Parser::make_REGEXP_SPACE(CURRENT_LOC); }
<REGEXP>"\\S"                      { return Parser::make_REGEXP_NON_SPACE(CURRENT_LOC); }
<REGEXP>"\\d"                      { return Parser::make_REGEXP_DIGIT(CURRENT_LOC); }
<REGEXP>"\\D"                      { return Parser::make_REGEXP_NON_DIGIT(CURRENT_LOC); }
<REGEXP>"\\b"                      { return Parser::make_REGEXP_WORD_BOUNDARY(CURRENT_LOC); }
<REGEXP>"\\B"                      { return Parser::make_REGEXP_NON_WORD_BOUNDARY(CURRENT_LOC); }
<REGEXP>"\\"                       {
	using namespace std::string_literals; // operator ""s
	char escapedChar = yyinput(); // Read next character from the input
	return Parser::make_REGEXP_CHAR("\\"s + escapedChar, CURRENT_LOC);
}
<REGEXP>"[^]"                      {
	// This is special case for negative class which wants to match ]
	// It must be the first character after [^
	_regexpClass = "^]";
	BEGIN(REGEXP_CLASS);
}
<REGEXP>"[]"                       {
	// This is special case for negative class which wants to match ]
	// It must be the first character after [
	_regexpClass = "]";
	BEGIN(REGEXP_CLASS);
}
<REGEXP>"[^"                       {
	_regexpClass = "^";
	BEGIN(REGEXP_CLASS);
}
<REGEXP>"["                        {
	_regexpClass.clear();
	BEGIN(REGEXP_CLASS);
}
<REGEXP_CLASS>"]"                  {
	BEGIN(REGEXP);
	return Parser::make_REGEXP_CLASS(_regexpClass, CURRENT_LOC);
}
<REGEXP_CLASS>"\\w"                { _regexpClass += "\\w"; }
<REGEXP_CLASS>"\\W"                { _regexpClass += "\\W"; }
<REGEXP_CLASS>"\\s"                { _regexpClass += "\\s"; }
<REGEXP_CLASS>"\\S"                { _regexpClass += "\\S"; }
<REGEXP_CLASS>"\\d"                { _regexpClass += "\\d"; }
<REGEXP_CLASS>"\\D"                { _regexpClass += "\\D"; }
<REGEXP_CLASS>"\\b"                { _regexpClass += "\\b"; }
<REGEXP_CLASS>"\\B"                { _regexpClass += "\\B"; }
<REGEXP_CLASS>.                    { _regexpClass += yytext[0]; }

{newline}                          { _driver.moveLineLocation(); }
{whitespace}*                      { }
<<EOF>>                            {
	if (!_driver.includeEnd())
		return yyterminate();
}
<*>.|\n                            { return yyterminate(); }

%%

/**
 * Includes the stream into the lexer buffer.
 *
 * @param input Stream to include.
 */
void Lexer::includeFile(std::istream* input)
{
	yypush_buffer_state(yy_create_buffer(input, YY_BUF_SIZE));
}

/**
 * Pops the top-most included file from the lexer buffer.
 *
 * @return @c true if pop succeeded, otherwise @c false.
 */
bool Lexer::includeEnd()
{
	yypop_buffer_state();
	if (!YY_CURRENT_BUFFER)
		return false;

	return true;
}

/**
 * Switches lexer back to its initial state for parsing general YARA tokens.
 * Behavior of lexer may be undefined if call of this method is not preceded with any @c switchToHexLexer() or @c switchToRegexpLexer()
 * or if this method is called multiple times without any call to @c switchToHexLexer() or @c switchToRegexpLexer() in the meantime.
 */
void Lexer::switchToYaraLexer()
{
	yy_pop_state();
}

/**
 * Switches lexer to state where it parses token for hex strings.
 * Behavior of lexer may be undefined if this method is called multiple times, or if method
 * @c switchToRegexpLexer() is used in the meantime without any preceding call of @c switchToYaraLexer().
 */
void Lexer::switchToHexLexer()
{
	yy_push_state(HEXSTR);
}

/**
 * Switches lexer to state where it parses token for regular expressions.
 * Behavior of lexer may be undefined if this method is called multiple times, or if method
 * @c switchToHexLexer() is used in the meantime without any preceding call of @c switchToYaraLexer().
 */
void Lexer::switchToRegexpLexer()
{
	yy_push_state(REGEXP);
}
