// Copyright (c) 2014-2019 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <iostream>
#include <string>
#include <fstream>

#include <pegtl/tao/pegtl.hpp>

namespace pegtl = TAO_PEGTL_NAMESPACE;

namespace syntax
{
   using namespace pegtl;

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

   struct _number : plus< ranges< '0', '9' > > {};
   struct _word : plus< sor< range< 'a', 'z'>, range< 'A', 'Z'>, range< '0', '9'>, one<'='>, string< '/', '"' >, one< '_' > > > {};
   struct _space : star< one <' '> > {};
   struct indent : seq< string< ' ',' ',' ',' ' > > {};

   struct rule_name : _word {};
   struct tag : _word {};

   struct meta_value : star< ranges< 'a', 'z', 'A', 'Z', '0', '9', ' '> > {};
   struct meta_key : star< ranges< 'a', 'z', 'A', 'Z', '_'> > {};
   struct meta_entry : seq< indent, indent, meta_key, string< ' ','=',' ','"' >, meta_value, one<'"'>, eol > {};
   struct meta : seq< indent, string< 'm','e','t','a',':' >, eol, plus< meta_entry >  > {};

   struct strings_modifier : seq< one< ' ' >, sor< string< 'a','s','c','i','i' >, string< 'f','u','l','l','w','o','r','d' >, string< 'n','o','c','a','s','e' >, string< 'w','i','d','e' > > > {};
   struct slash : seq< plus< one< '\\' > >, any > {};
   struct strings_value : until< at< one< '"' > >, sor< slash, any > > {};
   struct strings_key : seq< one< '$' >, ranges< 'a', 'z' >, _number > {};    //$?<cislo>
   struct strings_entry : seq< indent, indent, strings_key, string< ' ', '=', ' ', '"' >, strings_value, one<'"'>, star< strings_modifier >, opt< eol > > {};
   struct strings : seq< indent, string< 's','t','r','i','n','g','s',':'>, eol, plus< strings_entry > > {};


   struct condition_line : until< eol, any > {};
   struct condition_entry : seq< indent, indent, condition_line > {};
   struct condition : seq< indent, string< 'c','o','n','d','i','t','i','o','n',':' >, eol, plus< condition_entry > > {};

   struct grammar : seq< string< 'r','u','l','e',' ' >, rule_name, _space, sor< eol, seq< _space, one<':'>, plus< seq< _space, tag > >, _space,  opt< eol > > >,
   one< '{' >, eol,
   meta,
   opt< strings >,
   condition,
   one< '}' >, eof >
   {};

   // clang-format on

   struct State
   {
      std::string name;
      std::vector< std::string > tags;
      std::vector< std::string > meta_keys;
      std::vector< std::string > meta_values;
      std::vector< std::vector< token::yytokentype > > strings_tokens;
      std::vector< std::string > strings_keys;
      std::vector< std::string > strings_values;
      std::vector< std::string > condition;
   };

   template< typename Rule >
   struct action {};

   template<>
   struct action< rule_name >
   {
      template< typename Input >
      static void apply(const Input& in, State& state)
      {
         state.name = in.string();
      }
   };

   template<>
   struct action< meta_key >
   {
      template< typename Input >
      static void apply(const Input& in, State& state)
      {
         std::cout << "'Called meta_key action with '" << in.string() << std::endl;
         state.meta_keys.push_back(in.string());
      }
   };

   template<>
   struct action< tag >
   {
      template< typename Input >
      static void apply(const Input& in, State& state)
      {
         std::cout << "'Called tag action with '" << in.string() << std::endl;
         state.tags.push_back(in.string());
      }
   };

   template<>
   struct action< meta_value >
   {
      template< typename Input >
      static void apply(const Input& in, State& state)
      {
         std::cout << "'Called meta_value action with '" << in.string() << std::endl;
         state.meta_values.push_back(in.string());
      }
   };

   template<>
   struct action< condition_line >
   {
      template< typename Input >
      static void apply(const Input& in, State& state)
      {
         std::cout << "Called action condition_line with '" << in.string() << "'" << std::endl;
         state.condition.push_back(in.string());
      }
   };

   template<>
   struct action< strings_modifier >
   {
      template< typename Input >
      static void apply(const Input& in, State& state)
      {
         std::cout << "Called action strings_modifier with '" << in.string() << "'" << std::endl;
         state.strings_tokens.back().push_back(token::type(in.string()));
      }
   };

   template<>
   struct action< strings_entry >
   {
      template< typename Input >
      static void apply(const Input& in, const State& /*unused*/)
      {
         std::cout << "Called action strings_entry with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< strings_key >
   {
      template< typename Input >
      static void apply(const Input& in, State& state)
      {
         std::cout << "Called action strings_key with '" << in.string() << "'" << std::endl;
         state.strings_keys.push_back(in.string());
         state.strings_tokens.emplace_back();
      }
   };

   template<>
   struct action< strings_value >
   {
      template< typename Input >
      static void apply(const Input& in, State& state)
      {
         std::cout << "Called action strings_value with '" << in.string() << "'" << std::endl;
         state.strings_values.push_back(in.string());
      }
   };

   struct Parser {
      State state;
      std::ifstream in_stream;
      uint max_size = 0;

      Parser(std::ifstream&& stream, uint max_size)
         : in_stream(std::move(stream))
         , max_size(max_size)
      {
      }

      Parser(const std::string& source_file, uint max_size)
         : max_size(max_size)
      {
         in_stream.open(source_file, std::ifstream::in);
      }

//    Parser( const std::string& input )
//    {
//    }

      int parse() {
         auto input = pegtl::istream_input(in_stream, max_size, "from_content");

         auto result = pegtl::parse< grammar, action >(input);
         if(result)
            std::cout << "parsing OK" << std::endl;
         else
            std::cout << "parsing failed" << std::endl;
         return result;
      }

      void printResultForDebug() { //TODO: DELETE BEFORE DEPLOY
         std::cout << "Parsed rule " << state.name << "with the following tags: " << std::endl;
         for(const auto& tag : state.tags)
            std::cout << tag << ", ";
         std::cout << "and metas: " << std::endl;
         for(size_t i = 0; i < state.meta_keys.size(); ++i)
            std::cout << "Meta " << state.meta_keys[i] << " has value " << state.meta_values[i] << "." << std::endl;

         std::cout << "Parsed strings:" << std::endl;
         for(size_t i = 0; i < state.strings_keys.size(); ++i) {
            std::cout << "String " << state.strings_keys[i] << " has value " << state.strings_values[i] << " and modifiers:" << std::endl;
               for(const auto& modifier : state.strings_tokens[i])
                  std::cout << modifier << std::endl;
         }
         std::cout << "Parsed condition:" << std::endl;
         for(const auto& line : state.condition)
            std::cout << line;
      }
   };

}  // namespace syntax
