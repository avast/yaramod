/**
 * @file src/parser/parser_driver.h
 * @brief Declaration of class ParserDriver.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#pragma once

#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <fstream>

#include <pegtl/tao/pegtl.hpp>

#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/parser/parser_driver.h"

namespace pgl = TAO_PEGTL_NAMESPACE;

namespace yaramod {

class ParserDriver;

namespace pp {

namespace gr {

   using namespace pgl;

   struct _number : plus< ranges< '0', '9' > > {};
   struct _word : plus< sor< ranges< 'a', 'z',  'A', 'Z', '0', '9' >, one<'='>, string< '/','"' >, one<'_'> > > {};
   struct _space : star< one <' '> > {};
   struct indent : seq< string< ' ',' ',' ',' ' > > {};

   struct rule_name : _word {};
   struct tag : _word {};

   struct meta_value : star< ranges< 'a', 'z', 'A', 'Z', '0', '9', ' '> > {};
   struct meta_key : star< ranges< 'a', 'z', 'A', 'Z', '_'> > {};
   struct meta_entry : seq< indent, indent, meta_key, string< ' ','=',' ','"' >, meta_value, one<'"'>, eol > {};
   struct meta : seq< indent, string< 'm','e','t','a',':' >, eol, plus< meta_entry >  > {};

   struct strings_modifier : seq< one< ' ' >, sor< string< 'a','s','c','i','i' >, string< 'f','u','l','l','w','o','r','d' >, string< 'n','o','c','a','s','e' >, string< 'w','i','d','e' > > > {};
   struct slash : seq< plus< one< '\\' > >, pgl::any > {};
   struct strings_value : until< at< one< '"' > >, sor< slash, pgl::any > > {};
   struct strings_key : seq< one< '$' >, ranges< 'a', 'z' >, _number > {};    //$?<cislo>
   struct strings_entry : seq< indent, indent, strings_key, string< ' ', '=', ' ', '"' >, strings_value, one<'"'>, star< strings_modifier >, opt< eol > > {};
   struct strings : seq< indent, string< 's','t','r','i','n','g','s',':'>, eol, plus< strings_entry > > {};


   struct condition_line : until< eol, pgl::any > {};
   struct condition_entry : seq< indent, indent, condition_line > {};
   struct condition : seq< indent, string< 'c','o','n','d','i','t','i','o','n',':' >, eol, plus< condition_entry > > {};

   struct grammar : seq<
   string< 'r','u','l','e',' ' >, rule_name, _space,
   sor< eol, seq< _space, one<':'>, plus< seq< _space, tag > >, _space,  opt< eol > > >,
   one< '{' >, eol,
   meta,
   opt< strings >,
   condition,
   one< '}' >, eof >
   {};


   struct token
   {
      enum yytokentype
      {
         END = 258,
         RANGE = 259,
         DOT = 260,
         LT = 261,
         GT = 262,
         LE = 263,
         GE = 264,
         EQ = 265,
         NEQ = 266,
         SHIFT_LEFT = 267,
         SHIFT_RIGHT = 268,
         MINUS = 269,
         PLUS = 270,
         MULTIPLY = 271,
         DIVIDE = 272,
         MODULO = 273,
         BITWISE_XOR = 274,
         BITWISE_AND = 275,
         BITWISE_OR = 276,
         BITWISE_NOT = 277,
         LP = 278,
         RP = 279,
         LCB = 280,
         RCB = 281,
         ASSIGN = 282,
         COLON = 283,
         COMMA = 284,
         PRIVATE = 285,
         GLOBAL = 286,
         RULE = 287,
         META = 288,
         STRINGS = 289,
         CONDITION = 290,
         ASCII = 291,
         NOCASE = 292,
         WIDE = 293,
         FULLWORD = 294,
         XOR = 295,
         BOOL_TRUE = 296,
         BOOL_FALSE = 297,
         IMPORT_MODULE = 298,
         NOT = 299,
         AND = 300,
         OR = 301,
         ALL = 302,
         ANY = 303,
         OF = 304,
         THEM = 305,
         FOR = 306,
         ENTRYPOINT = 307,
         OP_AT = 308,
         OP_IN = 309,
         FILESIZE = 310,
         CONTAINS = 311,
         MATCHES = 312,
         SLASH = 313,
         STRING_LITERAL = 314,
         INTEGER = 315,
         DOUBLE = 316,
         STRING_ID = 317,
         STRING_ID_WILDCARD = 318,
         STRING_LENGTH = 319,
         STRING_OFFSET = 320,
         STRING_COUNT = 321,
         ID = 322,
         INTEGER_FUNCTION = 323,
         HEX_OR = 324,
         LSQB = 325,
         RSQB = 326,
         HEX_WILDCARD = 327,
         DASH = 328,
         HEX_NIBBLE = 329,
         HEX_INTEGER = 330,
         REGEXP_OR = 331,
         REGEXP_ITER = 332,
         REGEXP_PITER = 333,
         REGEXP_OPTIONAL = 334,
         REGEXP_START_OF_LINE = 335,
         REGEXP_END_OF_LINE = 336,
         REGEXP_ANY_CHAR = 337,
         REGEXP_WORD_CHAR = 338,
         REGEXP_NON_WORD_CHAR = 339,
         REGEXP_SPACE = 340,
         REGEXP_NON_SPACE = 341,
         REGEXP_DIGIT = 342,
         REGEXP_NON_DIGIT = 343,
         REGEXP_WORD_BOUNDARY = 344,
         REGEXP_NON_WORD_BOUNDARY = 345,
         REGEXP_CHAR = 346,
         REGEXP_RANGE = 347,
         REGEXP_CLASS = 348,
         UNARY_MINUS = 349,
         INVALID = 16384
      };

      static yytokentype type( const std::string& str ) {
         if(str == " ascii")
            return token::ASCII;
         if(str == " wide")
            return token::WIDE;
         if(str == " nocase")
            return token::NOCASE;
         if(str == " fullword")
            return token::FULLWORD;
         return token::INVALID;
      }
   };

   template< typename Rule >
   struct action {};

   template<>
   struct action< rule_name >
   {
      template< typename Input >
      static void apply(const Input& in, yaramod::YaraRuleBuilder& builder)
      {
//         state.name = in.string();
         builder.withName(in.string());
      }
   };

   template<>
   struct action< meta_key >
   {
      template< typename Input >
      static void apply(const Input& in, const yaramod::YaraRuleBuilder& /*unused*/)
      {
         std::cout << "'Called meta_key action with '" << in.string() << std::endl;
//         state.meta_keys.push_back(in.string());
      }
   };

   template<>
   struct action< tag >
   {
      template< typename Input >
      static void apply(const Input& in, const yaramod::YaraRuleBuilder& /*unused*/)
      {
         std::cout << "'Called tag action with '" << in.string() << std::endl;
//         state.tags.push_back(in.string());
      }
   };

   template<>
   struct action< meta_value >
   {
      template< typename Input >
      static void apply(const Input& in, const yaramod::YaraRuleBuilder& /*unused*/)
      {
         std::cout << "'Called meta_value action with '" << in.string() << std::endl;
//         state.meta_values.push_back(in.string());
      }
   };

   template<>
   struct action< condition_line >
   {
      template< typename Input >
      static void apply(const Input& in, const yaramod::YaraRuleBuilder& /*unused*/)
      {
         std::cout << "Called action condition_line with '" << in.string() << "'" << std::endl;
//        state.condition.push_back(in.string());
      }
   };

   template<>
   struct action< strings_modifier >
   {
      template< typename Input >
      static void apply(const Input& in, const yaramod::YaraRuleBuilder& /*unused*/)
      {
         std::cout << "Called action strings_modifier with '" << in.string() << "'" << std::endl;
//         state.strings_tokens.back().push_back(token::type(in.string()));
      }
   };

   template<>
   struct action< strings_entry >
   {
      template< typename Input >
      static void apply(const Input& in, const yaramod::YaraRuleBuilder& /*unused*/)
      {
         std::cout << "Called action strings_entry with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< strings_key >
   {
      template< typename Input >
      static void apply(const Input& in, const yaramod::YaraRuleBuilder& /*unused*/)
      {
         std::cout << "Called action strings_key with '" << in.string() << "'" << std::endl;
//         state.strings_keys.push_back(in.string());
//         state.strings_tokens.emplace_back();
      }
   };

   template<>
   struct action< strings_value >
   {
      template< typename Input >
      static void apply(const Input& in, const yaramod::YaraRuleBuilder& /*unused*/)
      {
         std::cout << "Called action strings_value with '" << in.string() << "'" << std::endl;
//         state.strings_values.push_back(in.string());
      }
   };

} //namespace gr


   class Parser {
      ParserDriver& driver;
      YaraRuleBuilder builder;
      std::vector< std::unique_ptr< std::istream > > streams;
      std::istream* initial_stream = nullptr;
      uint max_size = 0;
      int current_stream = -1;

   public:

      Parser(ParserDriver& driver, std::istream& input, uint max_size)
         : driver(driver)
         , initial_stream(&input)
         , max_size(max_size)
      {
         current_stream = -1;
      }

      Parser(ParserDriver& driver, const std::string& input_path, uint max_size)
         : driver(driver)
//         , initial_stream(nullptr)
      {
         includeStream(input_path, max_size);
         current_stream = 0;
      }

      void includeStream(std::unique_ptr< std::istream >&& input, uint max_size) { //nahrada lexer::includeFile
         streams.push_back(std::move(input));
         this->max_size = max_size;
      }

      void includeStream(const std::string& source_file, uint max_size) {
         auto ptr = std::make_unique< std::ifstream >( source_file, std::ifstream::in );
         streams.push_back(std::move(ptr));
         this->max_size = max_size;
      }

      std::istream* nextStream() {
         return initial_stream;
         /*if(initial_stream) TODO
         {
            if(current_stream_id == -1)
            {
               current_stream_id = 0;
               return initial_stream;
            }
            else
            {
               ++current_stream_id;
            }
         }
         else return streams[0].get();*/
      }

      int parse() {
         std::cout << "Parser::parse called" << std::endl;
         auto stream = nextStream();
         auto input = pgl::istream_input(*stream, max_size, "from_content");

         auto result = pgl::parse< gr::grammar, gr::action >(input, builder);
         std::unique_ptr<Rule> rule = builder.get();
         //driver->_file.addRule(rule);

         if(result)
            std::cout << "parsing OK" << std::endl;
         else
            std::cout << "parsing failed" << std::endl;

         return result;
      }
   };

}  // namespace pp
}  // namespace yaramod
