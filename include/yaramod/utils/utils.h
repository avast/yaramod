/**
 * @file src/utils/utils.h
 * @brief Declaration of utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <sstream>
#include <string>

namespace yaramod {

bool isValidIdentifier(const std::string& id);
std::string escapeString(const std::string& str);

bool endsWith(const std::string& str, const std::string& withWhat);
bool endsWith(const std::string& str, char withWhat);

std::string trim(std::string str);

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
std::string numToStr(const T num, std::ios_base &(*format)(std::ios_base&) = std::dec, bool showbase = false)
{
	std::ostringstream os;
	if (showbase)
		os << format << std::showbase << num;
	else
		os << format << num;
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

}
