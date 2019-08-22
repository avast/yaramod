// Copyright (c) 2018-2019 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAO_PEGTL_INTERNAL_ALWAYS_FALSE_HPP
#define TAO_PEGTL_INTERNAL_ALWAYS_FALSE_HPP

#include "../config.hpp"

#include <type_traits>

namespace TAO_PEGTL_NAMESPACE::internal
{
   template< typename... >
   struct always_false
      : std::false_type
   {
   };

}  // namespace TAO_PEGTL_NAMESPACE::internal

#endif
