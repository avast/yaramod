/**
 * @file include/yaramod/utils/utils.h
 * @brief Declaration of utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <cctype>
#include <sstream>
#include <string>
#include <cmath>

namespace yaramod {

bool isValidIdentifier(const std::string& id);
std::string escapeString(const std::string& str);
std::string unescapeString(std::string_view str);

bool endsWith(const std::string& str, const std::string& withWhat);
bool endsWith(const std::string& str, char withWhat);

std::string trim(std::string str, const std::string& toTrim = " \n\r\t\v");

/**
 * Checks whether string starts with another string or character.
 *
 * @param str String to check.
 * @param withWhat Prefix to check.
 *
 * @return `true` if it starts, otherwise `false`.
 */
template <typename T>
bool startsWith(const std::string& str, const T& withWhat)
{
	return str.find(withWhat) == 0;
}

/**
 * Converts number to string according to the specified format. Prepends base of number if requested.
 *
 * @param num Number to convert.
 * @param format Format to use when converting.
 * @param showbase Indicates whether to prepend base or not.
 *
 * @return Number converted to string.
 */
template <typename T>
std::string numToStr(const T num, std::ios_base &(*format)(std::ios_base&) = std::dec, bool showbase = false, bool toUpper = false)
{
	std::ostringstream os;

	// Set precision if num is floating point
	if (std::is_floating_point<T>::value)
		os.precision(std::numeric_limits<T>::digits10 - 1);

	os << std::fixed;
	if (toUpper)
		os << std::uppercase;
	if (showbase)
		os << format << std::showbase << num;
	else
		os << format << num;

	// Postprocess value if value is floating point
	if (std::is_floating_point<T>::value)
	{
		std::string value = os.str();
		auto comma = value.find('.');

		// Generated string presentation do not have comma add .0 (xxxx)
		if (comma == std::string::npos)
		{
			return value.append(".0");
		}
		// Generated string presentation have comma on last place (xxxx.)
		if (comma == value.length() - 1)
		{
			return value.append("0");
		}
		// Generated string have format xxx.x
		if (comma == value.length() - 2)
		{
			return value;
		}
		// Trim tailing zeros from generated float presentation (10.030000000 -> 10.03)
		auto zero = value.find_last_not_of('0');
		return {value.begin(), value.begin() + static_cast<long>(std::max(zero + 1, comma + 2))};
	}
	return os.str();
}

/**
 * Converts string to number according to the specified format.
 *
 * @param str String to convert.
 * @param[out] num Numeric result.
 * @param format Format of the number.
 *
 * @return `true` if conversion was successful, otherwise `false`.
 */
template <typename T>
bool strToNum(const std::string& str, T& num, std::ios_base &(*format)(std::ios_base&) = std::dec)
{
	std::istringstream is(str);
	T tmp = 0;
	is >> format >> tmp;
	if (!is.fail() && is.eof())
	{
		num = tmp;
		return true;
	}
	return false;
}

/**
 * With `isAnyOf` you can determine if one type is one of the other types in compile time.
 *
 * Usage:
 * isAnyOf<some_type, list_of_possible_types...>::value
 * `value` will be `true` or `false` depending whether `some_type` is in `list_of_possible_values`.
 *
 * Examples:
 * isAnyOf<int, long, float>::value == false
 * isAnyOf<int, long, float, int>::value == true
 */
template <typename T, typename... Args>
struct isAnyOf : std::false_type {};

template <typename T, typename Head, typename... Args>
struct isAnyOf<T, Head, Args...> : isAnyOf<T, Args...> {};

template <typename T, typename... Args>
struct isAnyOf<T, T, Args...> : std::true_type {};

}
