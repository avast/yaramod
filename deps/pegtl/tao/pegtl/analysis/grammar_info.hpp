// Copyright (c) 2014-2019 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAO_PEGTL_ANALYSIS_GRAMMAR_INFO_HPP
#define TAO_PEGTL_ANALYSIS_GRAMMAR_INFO_HPP

#include <map>
#include <string>
#include <utility>

#include "../config.hpp"
#include "../internal/demangle.hpp"

#include "rule_info.hpp"

namespace TAO_PEGTL_NAMESPACE::analysis
{
   struct grammar_info
   {
      using map_t = std::map< std::string, rule_info >;
      map_t map;

      template< typename Name >
      auto insert( const rule_type type )
      {
         return map.emplace( internal::demangle< Name >(), rule_info( type ) );
      }
   };

}  // namespace TAO_PEGTL_NAMESPACE::analysis

#endif
