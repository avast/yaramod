//    template<>
//    struct action< hex_normal >
//    {
//       template< typename Input >
//       static void apply(const Input& in, ParserDriver& d)
//       {
//          std::cout << "Matched hex_normal with '" << in.string() << "'" << std::endl;
//          const auto hex_n = std::stoi(in.string(), nullptr, 16);
//          d.hex_builder.add(hex_n);
// //       std::cout << "Result " << hex_n << std::endl;
//       }
//    };

//    template<>
//    struct action< hex_wildcard_high >
//    {
//       template< typename Input >
//       static void apply(const Input& in, ParserDriver& d)
//       {
// //       std::cout << "Matched hex_wildcard_high with '" << in.string() << "'" << std::endl;
//          assert(in.string().length() == 2);
//          const auto hex_high = std::stoi(in.string().substr(1,1), nullptr, 16);
//          assert(hex_high <= 16);
//          d.hex_builder.add(wildcardHigh(hex_high));
// //       std::cout << "Result " << hex_high << std::endl;
//       }
//    };

//    template<>
//    struct action< hex_wildcard_low >
//    {
//       template< typename Input >
//       static void apply(const Input& in, ParserDriver& d)
//       {
// //       std::cout << "Matched hex_wildcard_low with '" << in.string() << "'" << std::endl;
//          assert(in.string().length() == 2);
//          const auto hex_low = std::stoi(in.string().substr(0,1), nullptr, 16);
//          assert(hex_low <= 16);
//          d.hex_builder.add(wildcardLow(hex_low));
// //       std::cout << "Result " << hex_low << std::endl;
//       }
//    };

//    template<>
//    struct action< hex_wildcard_full >
//    {
//       template< typename Input >
//       static void apply(const Input& , ParserDriver& d)
//       {
// //       std::cout << "Matched hex_wildcard_full with '" << in.string() << "'" << std::endl;
//          d.hex_builder.add(wildcard());
//       }
//    };

//    template<>
//    struct action< hex_jump_varying >
//    {
//       template< typename Input >
//       static void apply(const Input& , ParserDriver& d)
//       {
// //       std::cout << "Matched hex_jump_varying with '" << in.string() << "'" << std::endl;
//          d.hex_builder.add(jumpVarying());
//       }
//    };

//    template<>
//    struct action< hex_jump_varying_range >
//    {
//       template< typename Input >
//       static void apply(const Input& in, ParserDriver& d)
//       {
//          std::cout << "Matched hex_jump_varying_range with '" << in.string() << "'" << std::endl;
//          d.hex_builder.add(jumpVaryingRange(d.hex_jump_number1));
//          d.hex_jump_number1 = -1;
//       }
//    };

//    template<>
//    struct action< hex_jump_range >
//    {
//       template< typename Input >
//       static void apply(const Input& in, ParserDriver& d)
//       {
//          std::cout << "Matched hex_jump_range with '" << in.string() << "'" << std::endl;
//          d.hex_builder.add(jumpRange(d.hex_jump_number1, d.hex_jump_number2));
//          d.hex_jump_number1 = d.hex_jump_number2 = -1;
//       }
//    };

//    template<>
//    struct action< hex_jump_fixed >
//    {
//       template< typename Input >
//       static void apply(const Input& in, ParserDriver& d)
//       {
//          std::cout << "Matched hex_jump_fixed with '" << in.string() << "'" << std::endl;
//          d.hex_builder.add(jumpFixed(d.hex_jump_number1));
//          d.hex_jump_number1 = -1;
//       }
//    };

//    template<>
//    struct action< hex_atom >
//    {
//       template< typename Input >
//       static void apply(const Input& in, const ParserDriver&)
//       {
//          std::cout << "Matched hex_atom with '" << in.string() << "'" << std::endl;
//       }
//    };

//    template<>
//    struct action< hex_brackets >
//    {
//       template< typename Input >
//       static void apply(const Input& in, const ParserDriver&)
//       {
//          std::cout << "Matched hex_brackets with '" << in.string() << "'" << std::endl;
//       }
//    };

//    template<>
//    struct action< hex_comp_alt_no_brackets >
//    {
//       template< typename Input >
//       static void apply(const Input& in, const ParserDriver&)
//       {
//          std::cout << "Matched hex_comp_alt_no_brackets with '" << in.string() << "'" << std::endl;
//       }
//    };

//    template<>
//    struct action< opt_space >
//    {
//       template< typename Input >
//       static void apply(const Input& in, const ParserDriver&)
//       {
//          std::cout << "Matched opt_space with '" << in.string() << "'" << std::endl;
//       }
//    };

//    template<>
//    struct action< hex_alt >
//    {
//       template< typename Input >
//       static void apply(const Input& in, const ParserDriver&)
//       {
//          std::cout << "Matched hex_alt with '" << in.string() << "'" << std::endl;
//       }
//    };

//    template<>
//    struct action< hex_comp >
//    {
//       template< typename Input >
//       static void apply(const Input& in, const ParserDriver&)
//       {
//          std::cout << "Matched hex_comp with '" << in.string() << "'" << std::endl;
//       }
//    };


//    template<>
//    struct action< hex_strings_value >
//    {
//       template< typename Input >
//       static void apply( const Input&, const ParserDriver&)
//       {
//       }
//   };
