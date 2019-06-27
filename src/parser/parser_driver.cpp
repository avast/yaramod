/**
 * @file src/parser/parser_driver.cpp
 * @brief Implementation of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <string>

#include <pegtl/tao/pegtl/contrib/parse_tree_to_dot.hpp>

#include "yaramod/parser/parser_driver.h"
#include "yaramod/utils/filesystem.h"
#include "yaramod/types/expressions.h"


#include <pegtl/tao/pegtl/parse_error.hpp>
#include <pegtl/tao/pegtl/tracking_mode.hpp>
#include <pegtl/tao/pegtl/contrib/tracer.hpp>
//#include <pegtl/tao/pegtl/istream_input.hpp>

namespace yaramod {

namespace gr {

	void error_handle( const std::string& msg, std::size_t line, std::optional<std::size_t> byte = std::nullopt, std::optional<std::size_t> length = std::nullopt, bool except = true )
	{
		std::stringstream ss;
		ss << "Error at ";
		if( byte ) {
			ss << line << "." << byte.value() + 1;
			if( length )
				ss << "-" << byte.value() + length.value();
		}
		else
			ss << "line " << line;
		ss << ": " << msg;
		if( except )
			throw ParserError( ss.str() );
		else
			std::cerr << ss.str() << std::endl;
	}

	void error_handle( const std::string& msg )
	{
		throw ParserError(msg);
	}

	template<>
   struct action< rule_name >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
	      	if(d._parsed_rule_names.count(in.string()) != 0)
					error_handle( std::string("Redefinition of rule '") + in.string() + "'", in.position().line, in.position().byte_in_line, in.string().size() );
	         d.builder.withName(in.string());
	         d.tokens.emplace_back(Tokentype::RULE_NAME, in.string(), in.position());
      }
   };

	template<>
   struct action< private_rule_modifier >
   {
      template< typename Input >
      static void apply(const Input&, ParserDriver& d)
      {
      	d.builder.withModifier(Rule::Modifier::Private);
      }
   };

	template<>
   struct action< global_rule_modifier >
   {
      template< typename Input >
      static void apply(const Input&, ParserDriver& d)
      {
			d.builder.withModifier(Rule::Modifier::Global);
      }
   };

   template<>
   struct action< import_name >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& d)
   	{
   		if (!d._file.addImport(in.string()))
			{
				error_handle(std::string("Unrecognized module '") + in.string() + "' imported", in.position().line, in.position().byte_in_line, in.string().size());
			}
   	}
   };

   template<>
   struct action< tag >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.builder.withTag(in.string());
         d.tokens.emplace_back(Tokentype::TAG, in.string(), in.position());
      }
   };

   template<>
   struct action< meta_key >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.meta_key = in.string();
         d.tokens.emplace_back(Tokentype::META_KEY, in.string(), in.position());
      }
   };

   template<>
   struct action< meta_string_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.builder.withStringMeta(d.meta_key, in.string());
         d.tokens.emplace_back(Tokentype::META_VALUE, in.string(), in.position());
      }
   };

   template<>
   struct action< meta_int_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         int64_t meta_value = std::stoi(in.string());
         d.builder.withUIntMeta(d.meta_key, meta_value);
         d.tokens.emplace_back(Tokentype::META_VALUE, meta_value, in.position());
      }
   };

   template<>
   struct action< meta_hex_uint_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
//         std::cout << "'Matched meta_hex_uint_value action with '" << in.string() << "'" << std::endl;
         int64_t meta_value = std::stoi(in.string(), nullptr, 16);
         d.builder.withHexIntMeta(d.meta_key, meta_value);
         d.tokens.emplace_back(Tokentype::META_VALUE, meta_value, in.position());
      }
   };

   template<>
   struct action< meta_bool_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
//         std::cout << "'Matched meta_bool_value action with '" << in.string() << "'" << std::endl;
         if(in.string() == "true") {
            d.builder.withBoolMeta(d.meta_key, true);
	         d.tokens.emplace_back(Tokentype::META_VALUE, true, in.position());
	      }
         else if(in.string() == "false") {
            d.builder.withBoolMeta(d.meta_key, false);
	         d.tokens.emplace_back(Tokentype::META_VALUE, false, in.position());
	      }
         else
         	assert(false && "Internal error: meta_bool_value value must match 'true' or 'false' only");
         d.meta_key = "";
      }
   };

   // template<>
   // struct action< first_symbol_identificator >
   // {
   // 	template< typename Input >
   // 	static void apply(const Input& in, ParserDriver& d)
   // 	{
   // 		std::cout << "symbol_identificator matched with '" << in.string() << "'" << std::endl;
   // 		d.tmp_external_symbol = std::move(in.string());
   // 	}
   // };

   // This action only checks the first symbol identificator. The proper check is performed in the parse_cond_tree method.
//    template<>
//    struct action< external_symbol >
//    {
//    	template< typename Input >
//    	static void apply(const Input& in, ParserDriver& d)
//    	{
//    		std::shared_ptr<Symbol> first = d._file.findSymbol(d.tmp_external_symbol);
//    	   if(!first)
//    	   {
//    			error_handle( "Unknown symbol '" + first->getName() + "'.", in.position().line );
//    	   }
// //   	   const auto type = first.getDataType();

//    	   if( first->getDataType() == Expression::Type::Object )
// 	   		std::cout << "external_symbol matched with object '" << in.string() << "'" << std::endl;
//    	   if( first->getDataType() == Expression::Type::String )
// 	   		std::cout << "external_symbol matched with string '" << in.string() << "'" << std::endl;
//    	   if( first->getDataType() == Expression::Type::Int )
// 	   		std::cout << "external_symbol matched with int '" << in.string() << "'" << std::endl;
//    	   if( first->getDataType() == Expression::Type::Bool )
// 	   		std::cout << "external_symbol matched with bool '" << in.string() << "'" << std::endl;
//    	   if( first->getDataType() == Expression::Type::Float )
// 	   		std::cout << "external_symbol matched with float '" << in.string() << "'" << std::endl;
//    	   if( first->getDataType() == Expression::Type::Regexp )
// 	   		std::cout << "external_symbol matched with regexp '" << in.string() << "'" << std::endl;
//    	   /*
//    	   for(size_t i = 1; i < d.tmp_external_symbols.size(); ++i){

//    	   }*/
//    	}
//    };

   template<>
   struct action< cond_number >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& )
   	{
   		std::cout << "cond_number matched with '" << in.string() << "'" << std::endl;
   	}
   };

   template<>
   struct action< cond_entrypoint >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& )
   	{
   		std::cout << "cond_entrypoint matched with '" << in.string() << "'" << std::endl;
   	}
   };

   template<>
   struct action< cond_formula_or >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& )
   	{
   		std::cout << "cond_formula_or matched with '" << in.string() << "'" << std::endl;
   	}
   };

   template<>
   struct action< condition_block >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& d)
   	{
   		string_input si( in.string(), "cond" );
         std::unique_ptr< pgl::parse_tree::node > root;
         try {
         	root = pgl::parse_tree::parse< cond_formula_start, cond_selector, action > (si, d);
         }
      	catch( const std::exception& e ) {
      		error_handle( "Parsing condition '" + in.string() + "' failed with " + e.what() + ".", in.position().line );
      	}
      	if( root )
      	{
//	      	pgl::parse_tree::print_dot( std::cerr, *root );
	      	const auto& condition = ( parse_cond_tree( root.get(), d ) ).get();
//	      	std::cout << "XXX Parsed condition: '" << condition->getText() << "'" << std::endl;
   		   d.builder.withCondition( condition );
   		}
	      else
	      	error_handle( "Parsing the following condition was not successfull:\n" + in.string(), in.position().line );
		}
   };

   template<>
   struct action< strings_key >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.str_key = in.string();
         d.tokens.emplace_back(Tokentype::STRING_KEY, d.str_key, in.position());
      }
   };

   template<>
   struct action< plain_strings_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.plain_str_value = in.string();
         d.tokens.emplace_back(Tokentype::PLAIN_STRING_VALUE, in.string(), in.position());
      }
   };

   template<>
   struct action< plain_strings_entry >
   {
      template< typename Input >
      static void apply(const Input& /*unused*/, ParserDriver& d)
      {
         d.builder.withPlainString(d.str_key, d.plain_str_value, d.str_modifiers);
         d.str_key = "";
         d.plain_str_value = "";
         d.str_modifiers = 0u;
      }
   };

   template<>
   struct action< hex_strings_entry >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
			YaraHexStringBuilder hex_builder;
			string_input si( in.string(), "hex" );
         try {
         	auto root = pgl::parse_tree::parse< hex_comp_start, hex_selector > (si, d);
         	if(root)
         	{
	      		//pgl::parse_tree::print_dot( std::cout, *root );
	      		hex_builder.add(parse_hex_tree(root.get(), d.tokens));
	      	}
		      else
      	   	error_handle("Parsing hex-string '" + in.string() + "' failed.", in.position().line);
      		}
      	catch( const std::exception& e ) {
      		error_handle("Parsing hex-string '" + in.string() + "' failed.", in.position().line);
      	}

      	assert(d.str_modifiers == 0u);
         const auto& hex_string = hex_builder.get();
         const auto& units = hex_string->getUnits();
         if( units.front()->isJump() )
         	error_handle("hex-string syntax error: Unexpected jump '" + units.front()->getText() + "' at the beginning of hex-string, expecting ( or ? or nibble.", in.position().line);
         if( units.back()->isJump() )
         	error_handle("hex-string syntax error: Unexpected jump '" + units.back()->getText() + "' at the end of hex-string, expecting ( or ? or nibble.", in.position().line);
         d.builder.withHexString(d.str_key, hex_string);
         d.str_key = "";
      }
   };

   template<>
   struct action< strings_modifier_ascii >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.str_modifiers |= String::Modifiers::Ascii;
         d.tokens.emplace_back(Tokentype::ASCII, in.string(), in.position());
      }
   };

   template<>
   struct action< strings_modifier_nocase >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.str_modifiers |= String::Modifiers::Nocase;
         d.tokens.emplace_back(Tokentype::NOCASE, in.string(), in.position());
      }
   };

   template<>
   struct action< strings_modifier_wide >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.str_modifiers |= String::Modifiers::Wide;
         d.tokens.emplace_back(Tokentype::WIDE, in.string(), in.position());
      }
   };

   template<>
   struct action< strings_modifier_fullword >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.str_modifiers |= String::Modifiers::Fullword;
         d.tokens.emplace_back(Tokentype::FULLWORD, in.string(), in.position());
      }
   };
/*
   template<>
   struct action< end_of_rule >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
      	std::cout << "Rule was finished!";
   	   d.tokens.emplace_back(Tokentype::RULE_END, in.string(), in.position());
//   	   for( const auto& token : d.tokens )
//	   	   std::cout << token << "; ";
         d.finishRule();
      }
   };*/
/*
   template<>
   struct action< module_token >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
      	std::cout << "Module token '" << in.string() << "' matched." << std::endl;
      }
   };

   template<>
   struct action< module >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
      	std::cout << "Module '" << in.string() << "' matched." << std::endl;
      	//split the string to with delimeter . and then check if it is valid
      }
   };
*/
   template<>
   struct action< rule >
   {
      template< typename Input >
      static void apply(const Input&, ParserDriver& d)
      {
//   	   d.tokens.emplace_back(Tokentype::RULE_END, in.string(), in.position());
         d.finishRule();
      }
   };

   template<>
   struct action< end_of_file >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
   	   d.tokens.emplace_back(Tokentype::FILE_END, in.string(), in.position());
      }
   };

   void print_vector(const std::vector< YaraExpressionBuilder >& v)
   {
   	std::cout << "size:"<<v.size() << std::endl;
   	for(size_t i = 0; i < v.size(); ++i) {
   		std::cout << i << "-th item: " << v[i].get()->getText() << std::endl;
   	}
   }

/*struct e1_or :     list_must< e2_xor,    seq< opt_space_enter, _operator_bitwise_or,    opt_space_enter     > > {};
   struct e2_xor :    list_must< e3_and,    seq< opt_space_enter, _operator_bitwise_xor,   opt_space_enter     > > {};
   struct e3_and :    list_must< e4_shifts, seq< opt_space_enter, _operator_bitwise_and,   opt_space_enter     > > {};
   struct e4_shifts : list_must< e5_add,    seq< opt_space_enter, operator_shifts,         opt_space_enter     > > {};
   struct e5_add :    list_must< e6_mult,   seq< opt_space_enter, operator_additive,       opt_space_enter     > > {};
   struct e6_mult :   list_must< e7_neg,    seq< opt_space_enter, operator_multiplicative, opt_space_enter     > > {};
   struct e7_neg :      sor< e8_brackets,   seq< opt_space_enter, _operator_negation,      opt_space_enter, e7_neg > > {};
   struct e8_brackets : sor< seq< one<'('>, opt_space_enter, e1_or, opt_space_enter, one<')'>, opt_space_enter >, cond_comparable_atom > {};
   struct cond_expression : seq< opt_space_enter, e1_or, opt_space_enter > {};
*/

   YaraExpressionBuilder parse_cond_tree( pgl::parse_tree::node* n, ParserDriver& d/*, const std::set< Symbol::type >& allowed_types*/ )
   {
   	if( n->is_root() )
   	{
   		assert( n->children.size() <= 1 );
   		return parse_cond_tree( n->children.front().get(), d );
   	}
   	std::cout << "Called parse_cond_tree with '" << n->string() << "'" << std::endl;
   	if( n->is< cond_formula_or >() )
   	{
   		std::vector< YaraExpressionBuilder > disjuncts;
	   	for( const auto& child : n->children )
	   		disjuncts.emplace_back( parse_cond_tree( child.get(), d ) );
   		assert( disjuncts.size() >= 2 && "Internal error: wrong 'cond_formula_or' arity");
   		return disjunction( disjuncts ); // Bool
   	}
   	else if( n->is< cond_formula_and >() )
   	{
   		std::vector< YaraExpressionBuilder > conjuncts;
	   	for( const auto& child : n->children )
	   		conjuncts.emplace_back( parse_cond_tree( child.get(), d ) );
   		assert( conjuncts.size() >= 2 && "Internal error: wrong 'cond_formula_and' arity");
   		return conjunction( conjuncts ); // Bool
   	}
   	else if( n->is< cond_formula_item >() )
   	{
   		assert( n->children.size() >= 2 );
   		for( size_t i = 0; i < n->children.size() - 1; i++ ) {
   			assert( n->children[i]->is< cond_formula_not >() );
   			d.addToken( std::move( Token( NOT, n->children[i]->string(), n->children[i]->begin() ) ) );
   		}
   		auto bld = parse_cond_tree( n->children.back().get(), d );
   		for( size_t i = 0; i < n->children.size() - 1; i++ )
   			bld = !bld;
   		return bld;
   	}
   	else if( n->is< cond_string_length >() )
   	{
   		assert( n->children.size() == 1 || n->children.size() == 2 );
   		if( n->children.size() == 1 )
   			return matchLength( n->string() );
   		else
   			return matchLength( n->children.front()->string(), parse_cond_tree( n->children.back().get(), d ) );
   	}
   	else if( n->is< cond_string_offset >() )
   	{
   		assert( n->children.size() == 1 || n->children.size() == 2 );
			if( n->children.size() == 1 )
   			return matchOffset( n->string() );
   		else
   			return matchOffset( n->children.front()->string(), parse_cond_tree( n->children.back().get(), d ) );
   	}
   	else if( n->is< cond_number_with_opt_multiplier >() )
		{
			assert( n->children.size() == 1 || n->children.size() == 2 );
			auto mult = IntMultiplier::None;
			if( n->children.size() == 2 )
			{
				if( n->children.back()->is< cond_int_multiplier_kilo >() )
					mult = IntMultiplier::Kilobytes;
				else if( n->children.back()->is< cond_int_multiplier_mega >() )
					mult = IntMultiplier::Megabytes;
				else
					assert( n->children.back()->is< cond_int_multiplier_none >() );
			}
			const auto& num_child = n->children.front();
			assert( num_child->is< _number >() );
			assert( num_child->children.size() == 1 || num_child->children.size() == 2 );
			if( num_child->children.size() == 1 )
			{
				auto x = std::stoi( num_child->children.front()->string() );
				std::cout << "int " << x << std::endl;
				return intVal( x, mult );
   		}
			else
			{
				assert( ( mult == IntMultiplier::None) && "Double values with multipliers KB/MB are not supported." );
				auto x = std::stod( num_child->string() );
				std::cout << "double " << x << std::endl;
				return doubleVal( x );
   		}
		}
		else if(n->is< cond_int_function >() )
		{
			assert( n->children.size() == 2 || n->children.size() == 3 );
			auto base = stoi( n->children[0]->string() );
			bool be_flag = n->children.size() == 3;
			if( be_flag )
				assert( n->children[1]->is< cond_int_be_flag >() );
			auto endianness = be_flag ? IntFunctionEndianness::Big : IntFunctionEndianness::Little;
			if( base == 8 )
				return parse_cond_tree( n->children.back().get(), d ).readInt8( endianness );
			else if( base == 16 )
				return parse_cond_tree( n->children.back().get(), d ).readInt16( endianness );
			else if( base == 32 )
				return parse_cond_tree( n->children.back().get(), d ).readInt32( endianness );
			else
         	error_handle("Condition syntax error: base " + n->children[0]->string() + " used in '" + n->string() + "'  not supported. Use 8, 16 or 32.", n->begin().line);
      	return boolVal(false);
		}
		else if(n->is< cond_uint_function >() )
		{
			assert( n->children.size() == 2 || n->children.size() == 3 );
			auto base = stoi( n->children[0]->string() );
			bool be_flag = n->children.size() == 3;
			if( be_flag )
				assert( n->children[1]->is< cond_int_be_flag >() );
			auto endianness = be_flag ? IntFunctionEndianness::Big : IntFunctionEndianness::Little;
			if( base == 8 )
				return parse_cond_tree( n->children.back().get(), d ).readUInt8( endianness );
			else if( base == 16 )
				return parse_cond_tree( n->children.back().get(), d ).readUInt16( endianness );
			else if( base == 32 )
				return parse_cond_tree( n->children.back().get(), d ).readUInt32( endianness );
			else
         	error_handle("Condition syntax error: base " + n->children[0]->string() + " used in '" + n->string() + "'  not supported. Use 8, 16 or 32.", n->begin().line);
      	return boolVal(false);
		}
      else if( n->is< external_sequence >() )
      {
      	const auto& id = n->children[0]->string();
      	auto symbol = d.findSymbol(id);
			if (!symbol)
				error_handle("Unrecognized identifier '" + id + "' referenced");

			auto parent = YaraExpressionBuilder(std::make_shared<IdExpression>(symbol), symbol->getDataType());
      	if( n->children.size() <= 1 )
      		return parent;
      	else
      	{
      		//TODO remove this if else
//      		auto parent = id(n->children[0]->string());
	   		for( size_t i = 1; i < n->children.size(); ++i )
	       	{
					parent = parent.access( n->children[i]->string() );
	       	}
	      	std::cout << "We found some rule or global variable or module: '" << n->string() << "'." << std::endl;
	       	return parent;
   	  	}
      }
   	// Nodes of rules that do not have 0 children AND are not discussed in section **
   	else if( n->children.empty() )
   	{
   		if( n->is< _boolean >() )
   		{
   			if( n->string() == "true" )
	   			return boolVal( true );
	   		else if( n->string() == "false" )
	   			return boolVal( false );
	   		else assert( false && "Internal error: expected 'true' or 'false'." );
   		}
   		else if( n->is< cond_string_identificator >() )
   			return stringRef( n->string() );
   		else if( n->is< cond_filesize >() )
   			return filesize();
   		else if( n->is< cond_string_count >() )
   			return matchCount( n->string() );
   		else if( n->is< cond_entrypoint >() )
   			return entrypoint();
   		else if( n->is< cond_hex_number >() )
				return YaraExpressionBuilder( std::make_shared< IntLiteralExpression >( n->string() ) );
   		else if( n->is< _uint >() )
   			return intVal( std::stoi( n->string(), nullptr ) );
   		else
   		{
   			std::cerr << "Internal error: unknown leaf '" << n->string() << "' of type '" << n->name() << "'" << std::endl;
   			assert( false && "Internal error: unknown leaf." );
	   	}
   	}
   	else if( n->children.size() == 1 )
   	{
   		if( n->is< cond_number_brackets >() || n->is< cond_formula_brackets >() || n->is< cond_expression_brackets >() )
   			return paren( parse_cond_tree( n->children[0].get(), d ) );
   		else if( n->is< cond_relation >() )
				return parse_cond_tree(n->children[0].get(), d);
   		else {
   			std::cerr << "Internal error: unknown arity-1 node '" << n->string() << "' of type '" << n->name() << "'" << std::endl;
   			assert( false && "Internal error: unknown arity-1 node." );
	   	}
   	}
   	else if( n->children.size() >= 2 )
   	{
   		if( n->is< e1_or >() )
			{
				YaraExpressionBuilder bld = parse_cond_tree( n->children.front().get(), d );
		   	for( size_t i = 1; i < n->children.size(); ++i )
		   		bld = bld | parse_cond_tree( n->children[i].get(), d );
		   	return bld;
			}
			else if( n->is< e2_xor >() )
			{
				YaraExpressionBuilder bld = parse_cond_tree( n->children.front().get(), d );
		   	for( size_t i = 1; i < n->children.size(); ++i )
		   		bld = bld ^ parse_cond_tree( n->children[i].get(), d );
		   	return bld;
			}
   		else if( n->is< e3_and >() )
			{
				YaraExpressionBuilder bld = parse_cond_tree( n->children.front().get(), d );
		   	for( size_t i = 1; i < n->children.size(); ++i )
		   		bld = bld & parse_cond_tree( n->children[i].get(), d );
		   	return bld;
			}
   		else if( n->is< o4_shifts >() )
			{
				YaraExpressionBuilder bld = parse_cond_tree( n->children[0].get(), d );
		   	for( size_t i = 1; i < n->children.size(); ++i )
		   	{
		   		if( n->children[i]->is< _operator_shift_left >() )
			   		bld = bld << parse_cond_tree( n->children[++i].get(), d );
			   	else if( n->children[i]->is< _operator_shift_right >() )
			   		bld = bld >> parse_cond_tree( n->children[++i].get(), d );
			   	else
			   		assert(false && "Internal error: Unknown shift operator.");
		   	}
		   	return bld;
			}
   		else if( n->is< o5_add >() )
			{
				YaraExpressionBuilder bld = parse_cond_tree( n->children[0].get(), d );
		   	for( size_t i = 1; i < n->children.size(); ++i )
		   	{
		   		if( n->children[i]->is< _operator_plus >() )
			   		bld = bld + parse_cond_tree( n->children[++i].get(), d );
			   	else if( n->children[i]->is< _operator_minus >() )
			   		bld = bld - parse_cond_tree( n->children[++i].get(), d );
			   	else
			   		assert(false && "Internal error: Unknown additive operator.");
		   	}
		   	return bld;
			}
   		else if( n->is< o6_mult >() )
			{
				YaraExpressionBuilder bld = parse_cond_tree( n->children[0].get(), d );
		   	for( size_t i = 1; i < n->children.size(); ++i )
		   	{
		   		if( n->children[i]->is< _operator_multiply >() )
			   		bld = bld * parse_cond_tree( n->children[++i].get(), d );
			   	else if( n->children[i]->is< _operator_divide >() )
			   		bld = bld / parse_cond_tree( n->children[++i].get(), d );
			   	else if( n->children[i]->is< _operator_modulo >() )
			   		bld = bld % parse_cond_tree( n->children[++i].get(), d );
			   	else
			   		assert(false && "Internal error: Unknown multiplicative operator.");
		   	}
		   	return bld;
			}
   		else if( n->is< o7_neg >() )
			{
				return ! parse_cond_tree( n->children.back().get(), d );
			}
   		else if( n->is< e8_brackets >() )
			{
				return paren( parse_cond_tree( n->children.back().get(), d ) );
			}
   		else if( n->is< cond_string_offset >() )
   		{
   			assert( n->children.size() == 2 );
	   		return matchOffset( n->children.front()->string(), parse_cond_tree( n->children.back().get(), d ));
   		}
   		else if( n->is< cond_relation >() )
			{
				const auto& op = n->children[1];
				if( op->is< cond_relation_leq >() )
					return ( parse_cond_tree( n->children[0].get(), d ) <= parse_cond_tree( n->children[2].get(), d ) );
				if( op->is< cond_relation_l >() )
					return ( parse_cond_tree( n->children[0].get(), d ) <  parse_cond_tree( n->children[2].get(), d ) );
				if( op->is< cond_relation_geq >() )
					return ( parse_cond_tree( n->children[0].get(), d ) >= parse_cond_tree( n->children[2].get(), d ) );
				if( op->is< cond_relation_g >() )
					return ( parse_cond_tree( n->children[0].get(), d ) >  parse_cond_tree( n->children[2].get(), d ) );
				if( op->is< cond_relation_e >() )
					return ( parse_cond_tree( n->children[0].get(), d ) == parse_cond_tree( n->children[2].get(), d ) );
				if( op->is< cond_relation_ne >() )
					return ( parse_cond_tree( n->children[0].get(), d ) != parse_cond_tree( n->children[2].get(), d ) );
				else
				{
	   			std::cerr << "Internal error: unknown operator." << op->string() << std::endl;
	   			assert( false && "Internal error: unknown operator." );
	   		}
   		}
   		else if( n->is< cond_at_expression >() )
   			return matchAt( n->children[0]->string(), parse_cond_tree( n->children[1].get(), d ) );
   		else if( n->is< cond_in_expression >() )
   			return matchInRange( n->children[0]->string(), parse_cond_tree( n->children[1].get(), d ) );
   		else if( n->is< cond_range >() )
   			return range( parse_cond_tree( n->children[0].get(), d ), parse_cond_tree( n->children[1].get(), d ) );
   		else {
   			std::cerr << "Internal error: unknown token of arity " << n->children.size() << ": '" << n->string() << "' of type '" << n->name() << "'" << std::endl;
   			assert( false && "Internal error: unknown token." );
   		}
   	}
   	else {
   		std::cerr << "Internal error: unknown token '" << n->string() << "' of type '" << n->name() << "'" << std::endl;
   		assert( false && "Internal error: unknown token." );
   	}
   }


  	YaraHexStringBuilder parse_hex_tree( pgl::parse_tree::node* root, std::vector< yaramod::Token >& tokens )
  	{
  		std::vector<YaraHexStringBuilder> alt_builders;
  		alt_builders.emplace_back();
  		for ( const auto& child : root->children )
  		{
  			if( child->is< hex_atom_group >() )
  			{
  				alt_builders[0].add( parse_hex_tree( child.get(), tokens ) );
  			}
  			else if( child->is< hex_normal >() )
  			{
  				assert( child->string().length() == 2 );
   			auto hex = stoi( child->string(), nullptr, 16 );
  				alt_builders[0].add( hex );
  				tokens.emplace_back( Tokentype::HEX_NORMAL, hex, child->begin() );
  			}
  			else if( child->is< hex_wildcard_full >() )
  			{
  				alt_builders[0].add(wildcard());
  				tokens.emplace_back( Tokentype::HEX_WILDCARD_FULL, child->string(), child->begin() );
  			}
  			else if( child->is< hex_wildcard_high >() )
  			{
   			assert( child->string().length() == 2 );
   			const auto hex_high = std::stoi( child->string().substr(1,1), nullptr, 16 );
   			assert(hex_high <= 16);
   			alt_builders[0].add( wildcardHigh( hex_high ) );
  				tokens.emplace_back( Tokentype::HEX_WILDCARD_HIGH, hex_high, child->begin() );
  			}
  			else if( child->is< hex_wildcard_low >() )
  			{
  				assert( child->string().length() == 2 );
	   		const auto hex_low = std::stoi( child->string().substr(0,1), nullptr, 16 );
   			assert( hex_low <= 16 );
   			alt_builders[0].add( wildcardLow( hex_low ) );
  				tokens.emplace_back( Tokentype::HEX_WILDCARD_LOW, hex_low, child->begin() );
  			}
  			else if( child->is< hex_jump_varying >() )
  			{
  				alt_builders[0].add( jumpVarying() );
  				tokens.emplace_back( Tokentype::HEX_JUMP_VARYING, child->string(), child->begin() );
  			}
  			else if( child->is< hex_jump_varying_range >() ) //toto neni leaf, ale ma pod sebou jeste potomka _number :-)
  			{
  				assert( child->children.size() == 1 );
  				assert( child->children[0]->is< _uint >() );
  				int arg = std::stoi( child->children[0]->string() );
  				alt_builders[0].add( jumpVaryingRange( arg ) );
  				tokens.emplace_back( Tokentype::HEX_JUMP_VARYING_RANGE, arg, child->begin() );
  			}
  			else if( child->is< hex_jump_range >() )
  			{
  				assert( child->children.size() == 2 );
  				assert( child->children[0]->is< _uint >() );
  				assert( child->children[1]->is< _uint >() );
  				int left = std::stoi( child->children[0]->string() );
  				int right = std::stoi( child->children[1]->string() );
  				alt_builders[0].add( jumpRange( left, right ) );
  				tokens.emplace_back( Tokentype::HEX_JUMP_RANGE, child->string(), child->begin() );
  			}
  			else if( child->is< hex_jump_fixed >() )
  			{
  				assert( child->children.size() == 1 );
  				assert( child->children[0]->is< _uint >() );
  				int arg = std::stoi( child->children[0]->string() );
  				alt_builders[0].add( jumpFixed( arg ) );
  				tokens.emplace_back( Tokentype::HEX_JUMP_FIXED, arg, child->begin() );
  			}
  			else if( child->is< hex_brackets >() )
  			{
  				alt_builders[0].add( parse_hex_tree( child.get(), tokens ) );
  			}
  			else if(child->is< hex_alt >() ) {
  				alt_builders.emplace_back( parse_hex_tree( child.get(), tokens ) );
  			}
  			else if(child->is< hex_left_bracket >() ) {
  				tokens.emplace_back( Tokentype::HEX_LEFT_BRACKET, child->string(), child->begin() );
  			}
  			else if(child->is< hex_righ_bracket >() ) {
  				tokens.emplace_back( Tokentype::HEX_RIGHT_BRACKET, child->string(), child->begin() );
  			}
  			else {
  				assert(false && "Unknown node type.");
  			}
  		}
  		if( alt_builders.size() == 1 )
  			return alt_builders[0];
  		else
	  		return YaraHexStringBuilder(alt(alt_builders));
  	}

} // namespace gr

/**
 * Constructor.
 *
 * @param filePath Input file path.
 * @param parserMode Parsing mode.
 */
ParserDriver::ParserDriver(const std::string& filePath, ParserMode parserMode) : _mode(parserMode), _loc(nullptr),
   current_stream(0), _valid(true), _filePath(), _inputFile(), _file(), _currentStrings(), _stringLoop(false), _localSymbols(),
	_startOfRule(0), _anonStringCounter(0)
{

	// When creating ParserDriver from real file (not from some stringstream) we need to somehow tell lexer which file to process
	// yy::Lexer is not copyable nor assignable so we need to hack it through includes
	if (!includeFileImpl(filePath))
		_valid = false;
}

/**
 * Constructor.
 *
 * @param input Input stream.
 * @param parserMode Parsing mode.
 */
ParserDriver::ParserDriver(std::istream& input, ParserMode parserMode) : _mode(parserMode), _loc(nullptr),
	initial_stream(&input), _valid(true), _filePath(), _inputFile(), _file(), _currentStrings(), _stringLoop(false), _localSymbols()
{
/*
	auto is = pgl::istream_input(input, max_size, "from_content");
   auto result = pgl::parse< gr::grammar, gr::action >(is, *this);
*/
}

/**
 * Returns the lexer.
 *
 * @return Lexer.
 */
//yy::Lexer& ParserDriver::getLexer()
//{
//	return _lexer;
//}

/**
 * Returns the parser.
 *
 * @return parser.
 */
//yy::Parser& ParserDriver::getParser()
//{
//	return _parser;
//}

/**
 * Returns the location in the file.
 *
 * @return Location.
 */
const yy::location& ParserDriver::getLocation() const
{
	return _loc;
}

/**
 * Returns the result of parsing. The parsed YARA file.
 *
 * @return Parsed YARA file.
 */
YaraFile& ParserDriver::getParsedFile()
{
	return _file;
}

/**
 * Returns the result of parsing. The parsed YARA file.
 *
 * @return Parsed YARA file.
 */
const YaraFile& ParserDriver::getParsedFile() const
{
	return _file;
}


std::istream* ParserDriver::currentStream()
{
	if(initial_stream)
		return initial_stream;
	else
	   return _includedFiles[0].get();
}

/**
 * Parses the input stream or file.
 *
 * @return @c true if parsing succeeded, otherwise @c false.
 */
bool ParserDriver::parse()
{
	if (!_valid)
		return false;

	std::cerr << "ParserDriver::parse called" << std::endl;
   auto stream = currentStream();
   auto input = pgl::istream_input(*stream, max_size, "src");

//memory_input< tracking_mode::lazy, Eol > i2( data.data(), data.data() + data.size(), file );


   auto result = pgl::parse< gr::grammar, gr::action >(input, *this);

   if(result)
      std::cerr << "parsing OK" << std::endl;
   else
      std::cerr << "parsing failed" << std::endl;

	return result == 1;
}

/**
 * Returns whether the parser driver is in valid state.
 *
 * @return @c true if valid, otherwise @c false.
 */
bool ParserDriver::isValid() const
{
	return _valid;
}

/**
 * Moves one line further and resets the counter of columns.
 */
void ParserDriver::moveLineLocation()
{
	_loc.lines();
}

/**
 * Moves given number of columns further.
 *
 * @param moveLength Number of columns to move.
 */
void ParserDriver::moveLocation(std::uint64_t moveLength)
{
	_loc.step();
	_loc += moveLength;
}

void ParserDriver::addToken(const yaramod::Token& t)
{
	tokens.push_back(t);
}

void ParserDriver::addToken(yaramod::Token&& t)
{
	tokens.push_back(t);
}

/**
 * Includes file into input stream as it would be in place of @c include directive.
 *
 * @param includePath Path of file to include.
 *
 * @return @c true if include succeeded, otherwise @c false.
 */
bool ParserDriver::includeFile(const std::string& includePath)
{
	auto totalPath = includePath;
	if (pathIsRelative(includePath))
	{
		// We are not running ParserDriver from file input, just from some unnamed istream, therefore we need to forbid relative includes from
		// the top of the istream hierarchy
		if (_includedFileNames.empty() && _filePath.empty())
			return false;

		// Take the topmost file path from the stack.
		// This allows us to nest includes forming hierarchy of included files.
		totalPath = absolutePath(joinPaths(parentPath(_includedFileNames.back()), includePath));
	}

	return includeFileImpl(totalPath);
}

/**
 * Ends the include of the currently included file. This should normally happen when end-of-file is reached.
 * End of include may fail if there are no more files to pop from include stack.
 *
 * @return @c true if end of include succeeded, otherwise @c false.
 */
bool ParserDriver::includeEnd()
{
	if (!_includedFileNames.empty())
	{
		_includedFiles.pop_back();
		_includedFileNames.pop_back();
		_loc = _includedFileLocs.back();
		_includedFileLocs.pop_back();
	}

	//return _lexer.includeEnd();
	return false; //TODO fix this
}

/**
 * Returns whether rule with given name already exists.
 *
 * @param name Name of the rule.
 *
 * @return @c true if exists, @c false otherwise.
 */
bool ParserDriver::ruleExists(const std::string& name) const
{
	return std::any_of(_file.getRules().begin(), _file.getRules().end(),
			[&name](const auto& rule)
			{
				return rule->getName() == name;
			});
}

/**
 * Adds the rule into the YARA file and properly sets up its location.
 *
 * @param rule Rule to add.
 */
void ParserDriver::addRule(Rule&& rule)
{
	addRule(std::make_unique<Rule>(std::move(rule)));
}

/**
 * Adds the rule into the YARA file and properly sets up its location.
 *
 * @param rule Rule to add.
 */
void ParserDriver::addRule(std::unique_ptr<Rule>&& rule)
{
	if (!_includedFileNames.empty())
		rule->setLocation(_includedFileNames.back(), _startOfRule);
	bool success = _parsed_rule_names.insert(rule->getName()).second;
	if(!success)
		throw ParserError(std::string("Error at <TODO>: Redefinition of rule "+rule->getName()));
	else
		_file.addRule(std::move(rule));
}

void ParserDriver::finishRule()
{
   std::unique_ptr<Rule> rule = builder.get();
   addRule(std::move(rule));
}

/**
 * Marks the line number where the rule starts.
 */
void ParserDriver::markStartOfRule()
{
	_startOfRule = getLocation().end.line;
}

/**
 * Returns whether string with given identifier already exists in the current rule context.
 *
 * @param id Identifier of the string.
 *
 * @return @c true if exists, otherwise @c false.
 */
bool ParserDriver::stringExists(const std::string& id) const
{
	// Anonymous string references are available only in string-based for loops
	if (isInStringLoop() && id == "$")
		return true;

	auto currentStrings = _currentStrings.lock();
	if (!currentStrings)
		return false;

	// Is wildcard identifier
	if (endsWith(id, '*'))
	{
		auto idNonWild = id.substr(0, id.length() - 1);
		return currentStrings->isPrefix(idNonWild);
	}
	else
	{
		std::shared_ptr<String> string;
		return currentStrings->find(id, string);
	}

	return false;
}

/**
 * Sets the current strings trie for the context of the current rule.
 *
 * @param currentStrings Strings trie to set.
 */
void ParserDriver::setCurrentStrings(const std::shared_ptr<Rule::StringsTrie>& currentStrings)
{
	_currentStrings = currentStrings;
}

/**
 * Returns whether parser is in string-based for loop.
 *
 * @return @c true if is in string-based for loop, otherwise @c false.
 */
bool ParserDriver::isInStringLoop() const
{
	return _stringLoop;
}

/**
 * Sets that parser entered string-based for loop.
 */
void ParserDriver::stringLoopEnter()
{
	_stringLoop = true;
}

/**
 * Sets that parser left string-based for loop.
 */
void ParserDriver::stringLoopLeave()
{
	_stringLoop = false;
}

/**
 * Finds the symbol with the given name. It first searches in local symbols and then in global symbols.
 *
 * @param name Symbol name.
 *
 * @return Valid symbol if found, @c nullptr otherwise.
 */
std::shared_ptr<Symbol> ParserDriver::findSymbol(const std::string& name) const
{
	auto itr = _localSymbols.find(name);
	if (itr != _localSymbols.end())
		return itr->second;

	return _file.findSymbol(name);
}

/**
 * Adds the symbol to the local symbol table. If symbol with that name already exists, method fails.
 *
 * @param symbol Symbol to add.
 *
 * @return @c true if symbol was successfully added, otherwise @c false.
 */
bool ParserDriver::addLocalSymbol(const std::shared_ptr<Symbol>& symbol)
{
	if (findSymbol(symbol->getName()))
		return false;

	_localSymbols[symbol->getName()] = symbol;
	return true;
}

/**
 * Removes symbol with the given name from the local symbol table.
 *
 * @param name Name of the symbol to remove.
 */
void ParserDriver::removeLocalSymbol(const std::string& name)
{
	_localSymbols.erase(name);
}

/**
 * Indicates whether the string identifier is anonymous string
 * identifier. That means just '$' alone.
 *
 * @param stringId String identifier.
 * @return @c true if identifier of anonymous string, otherwise @c false.
 */
bool ParserDriver::isAnonymousStringId(const std::string& stringId) const
{
	return stringId == "$";
}

/**
 * Generates psuedoidentifier for anonymous string.
 *
 * @return Unique pseudoidentifier.
 */
std::string ParserDriver::generateAnonymousStringPseudoId()
{
	std::ostringstream str;
	str << "anon" << _anonStringCounter++;
	return str.str();
}

bool ParserDriver::isAlreadyIncluded(const std::string& includePath)
{
	return _includedFilesCache.find(absolutePath(includePath)) != _includedFilesCache.end();
}

bool ParserDriver::hasRuleWithName(const std::string& name) const
{
	return _parsed_rule_names.count(name) != 0;
}

bool ParserDriver::includeFileImpl(const std::string& includePath)//TODO: upravit
{
	if (_mode == ParserMode::IncludeGuarded && isAlreadyIncluded(includePath))
		return true;

	// We need to allocate ifstreams dynamically because they are not copyable and we need to store them
	// in vector to prolong their lifetime because of flex.
	auto includedFile = std::make_unique<std::ifstream>(includePath);
	if (!includedFile->is_open())
		return false;

	//_lexer.includeFile(includedFile.get());

	_includedFiles.push_back(std::move(includedFile));
	_includedFileNames.push_back(includePath);
	_includedFileLocs.push_back(_loc);
	_includedFilesCache.emplace(absolutePath(includePath));

	// Reset location se we can keep track of line numbers in included files
	_loc.begin.initialize(_loc.begin.filename, 1, 1);
	_loc.end.initialize(_loc.end.filename, 1, 1);
	return true;
}


/*
bool ParserDriver::includeEnd()
{
	// yypop_buffer_state();
	if (!YY_CURRENT_BUFFER)
		return false;

	return true;
}

void ParserDriver::includeFile(std::istream* input)
{
	//vlastni rozhrani kterym loadnu treba jiny file s jinym pravidlem
	//tady mas istream, ted parsuj z neho
	yypush_buffer_state(yy_create_buffer(input, YY_BUF_SIZE));
}
*/
} //namespace yaramod
