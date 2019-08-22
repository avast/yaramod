// Copyright (c) 2014-2019 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAO_PEGTL_INTERNAL_DEMANGLE_HPP
#define TAO_PEGTL_INTERNAL_DEMANGLE_HPP

#include <string>
#include <typeinfo>

#include "../config.hpp"

#if defined( __GLIBCXX__ ) || ( defined( __has_include ) && __has_include( <cxxabi.h> ) )
#include "demangle_cxxabi.hpp"
#else
#include "demangle_nop.hpp"
#endif

namespace TAO_PEGTL_NAMESPACE::internal
{
   template< typename T >
   [[nodiscard]] std::string demangle()
   {
      return demangle( typeid( T ).name() );
   }

}  // namespace TAO_PEGTL_NAMESPACE::internal

#endif
