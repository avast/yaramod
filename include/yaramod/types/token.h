/**
 * @file include/yaramod/parser/token.h
 * @brief Declaration of class Meta.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <cassert>
#include <pegtl/tao/pegtl.hpp>
#include <iostream>
#include <string>
#include <sstream>
#include <variant>


namespace yaramod{


/**
 * Class representing token values that YARA rules consist of. The values are stored in our inner representation, not the tokenstream.
 */
// class TokenValue// : public TokenValueBase
// {
// public:
//    /// @name Constructors
//    /// @{
//    TokenValue() = default;
//    TokenValue(int value) : value(value) {}
//    TokenValue(uint value) : value(value) {}
//    TokenValue(bool value) : value(value) {}
//    TokenValue(int64_t value) : value(value) {}
//    TokenValue(long unsigned int value) : value(value) {}
//    TokenValue(const std::string& value) : value(value) {}

//    TokenValue(TokenValue&& other) = default;
//    TokenValue(const TokenValue& other) = default;
//    /// @}

//    /// @name Assignment
//    /// @{
//    TokenValue& operator=(TokenValue&& other) = default;
//    TokenValue& operator=(const TokenValue& other) = default;
//    /// @}

//    /// @name Detection methods
//    /// @{
//    bool isBool() const
//    {
//       return std::is_same_v< decltype(value), bool& >;
//    }
//    bool isInt() const
//    {
//       return std::is_same_v< decltype(value), int& >;
//    }
//    bool isUint() const
//    {
//       return std::is_same_v< decltype(value), uint& >;
//    }
//    bool isUint64_t() const
//    {
//       return std::is_same_v< decltype(value), uint64_t& >;
//    }
//    bool isLongUnsignedInt() const
//    {
//       return std::is_same_v< decltype(value), long unsigned int& >;
//    }
//    bool isIntegral() const
//    {
//       return isInt() || isUint() || isUint64_t() || isLongUnsignedInt();
//    }
//    bool isString() const
//    {
//       return std::is_same_v< decltype(value), std::string& >;
//    }

//    friend std::ostream& operator<<(std::ostream& os, const TokenValue& token_value) {
//       std::visit(
//       [&os](auto&& v)
//          {
//             os << v;
//          },
//          token_value.value
//       );
//       return os;
//    }
//    /// @}

//    /// @name String representation
//    /// @{
//    std::string getText() const
//    {
//       std::stringstream ss;
//       if( isString() )
//          ss << "\"" << *this << "\"";
//       else
//          ss << *this;
//       return ss.str();
//    }

//    std::string getPureText() const
//    {
//       std::stringstream ss;
//       ss << *this;
//       return ss.str();
//    }
//    /// @}

//    /// @name Setter methods
//    /// @{
//    void setValue(int i) { value = i; }
//    void setValue(uint i) { value = i; }
//    void setValue(int64_t i) { value = i; }
//    void setValue(float i) { value = i; }
//    void setValue(long unsigned int i) { value = i; }
//    void setValue(bool b) { value = b; }
//    void setValue(const std::string& s) { value = s; }
//    /// @}

//    /// @name Getter methods
//    /// @{
//    int getIntegral() const
//    {
//       if(isInt())
//          return std::get<int>(value);
//       else if(isUint())
//          return std::get<uint>(value);
//       else if(isUint64_t())
//          return std::get<int64_t>(value);
//       else
//       {
//          std::cerr << "Called getIntegral() of a TokenValue which holds " << *this << ". Index = " << value.index() << std::endl;
//          assert(false && "Called getIntegral() of non-integral TokenValue");
//       }
//    }

//    float getFloat() const
//    {
//       try{
//          return std::get<float>(value);
//       }
//       catch (std::bad_variant_access& exp)
//       {
//          std::cerr << "Called getFloat() of a TokenValue which holds " << *this << ". Index = " << value.index() << std::endl << exp.what() << std::endl;
//          assert(false && "Called getFloat() of non-float TokenValue");
//       }
//    }

//    bool getBool() const
//    {
//       try{
//          return std::get<bool>(value);
//       }
//       catch (std::bad_variant_access& exp)
//       {
//          std::cerr << "Called getBool() of a TokenValue which holds " << *this << ". Index = " << value.index() << std::endl << exp.what() << std::endl;
//          assert(false && "Called getBool() of non-bool TokenValue");
//       }
//    }

//    const std::string& getString() const
//    {
//       try{
//          return std::get<std::string>(value);
//       }
//       catch (std::bad_variant_access& exp)
//       {
//          std::cerr << "Called getString() of a TokenValue which holds " << *this << ". Index = " << value.index() << std::endl << exp.what() << std::endl;
//          assert(false && "Called getString() of non-string TokenValue");
//       }
//    }
//    /// @}

// private:
//    std::variant<int, uint, int64_t, long unsigned int, float,  bool, std::string> value;
// };




} //namespace yaramod
