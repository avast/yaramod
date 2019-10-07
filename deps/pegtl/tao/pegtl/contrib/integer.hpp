// Copyright (c) 2018-2019 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAO_PEGTL_CONTRIB_INTEGER_HPP
#define TAO_PEGTL_CONTRIB_INTEGER_HPP

#include <limits>
#include <type_traits>

#include "../ascii.hpp"
#include "../parse_error.hpp"
#include "../rules.hpp"

namespace TAO_PEGTL_NAMESPACE::integer
{
   namespace internal
   {
      template< typename I, I Limit, typename Input >
      [[nodiscard]] I actual_convert( const Input& in, std::size_t index )
      {
         static constexpr I cutoff = Limit / 10;
         static constexpr I cutlim = Limit % 10;

         I out = in.peek_char( index ) - '0';
         while( ++index < in.size() ) {
            const I c = in.peek_char( index ) - '0';
            if( ( out > cutoff ) || ( ( out == cutoff ) && ( c > cutlim ) ) ) {
               throw parse_error( "integer out of range", in );
            }
            out *= 10;
            out += c;
         }
         return out;
      }

      template< typename I, typename Input >
      [[nodiscard]] I convert_positive( const Input& in, std::size_t index )
      {
         static constexpr I limit = ( std::numeric_limits< I >::max )();
         return actual_convert< I, limit >( in, index );
      }

      template< typename I, typename Input >
      [[nodiscard]] I convert_negative( const Input& in, std::size_t index )
      {
         using U = std::make_unsigned_t< I >;
         static constexpr U limit = static_cast< U >( ( std::numeric_limits< I >::max )() ) + 1;
         return static_cast< I >( ~actual_convert< U, limit >( in, index ) ) + 1;
      }

   }  // namespace internal

   struct unsigned_rule
      : plus< digit >
   {
   };

   struct unsigned_action
   {
      // Assumes that 'in' contains a non-empty sequence of ASCII digits.

      template< typename Input, typename State >
      static void apply( const Input& in, State& st )
      {
         using T = std::decay_t< decltype( st.converted ) >;
         static_assert( std::is_integral_v< T > );
         static_assert( std::is_unsigned_v< T > );
         st.converted = internal::convert_positive< T >( in, 0 );
      }
   };

   struct signed_rule
      : seq< opt< one< '+', '-' > >, plus< digit > >
   {
   };

   struct signed_action
   {
      // Assumes that 'in' contains a non-empty sequence of ASCII digits,
      // with optional leading sign; with sign, in.size() must be >= 2.

      template< typename Input, typename State >
      static void apply( const Input& in, State& st )
      {
         using T = std::decay_t< decltype( st.converted ) >;
         static_assert( std::is_integral_v< T > );
         static_assert( std::is_signed_v< T > );
         const auto c = in.peek_char();
         if( c == '-' ) {
            st.converted = internal::convert_negative< T >( in, 1 );
         }
         else {
            st.converted = internal::convert_positive< T >( in, std::size_t( c == '+' ) );
         }
      }
   };

}  // namespace TAO_PEGTL_NAMESPACE::integer

#endif
