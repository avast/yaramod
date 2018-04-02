/**
 * @file src/utils/utils.cpp
 * @brief Implementation of utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

#include "yaramod/utils/utils.h"

namespace yaramod {

/**
 * Checks whether the string is valid identifier for meta key or rule name.
 *
 * @return `true` if valid identifier, otherwise `false`.
 */
bool isValidIdentifier(const std::string& id)
{
	if (id.empty())
		return false;

	const unsigned char firstChar = id[0];
	if (!std::isalpha(firstChar) && firstChar != '_')
		return false;

	return std::all_of(id.begin() + 1, id.end(),
			[](const unsigned char c) {
				return c == '_' || std::isalnum(c);
			});
}

/**
 * Escapes the string according to the YARA escaping rules. Only escaping sequences are
 * `\n`, `\t`, `\"`, `\\` and `\xXX`.
 *
 * @param str String to escape.
 *
 * @return Escaped string.
 */
std::string escapeString(const std::string& str)
{
	std::ostringstream writer;
	std::string result;

	for (auto itr = str.begin(), end = str.end(); itr != end; ++itr)
	{
		const unsigned char c = *itr;
		switch (c)
		{
			case '\n':
				result += "\\n";
				break;
			case '\t':
				result += "\\t";
				break;
			case '\\':
			case '\"':
				result += "\\";
				result += *itr;
				break;
			default:
				if (std::isprint(c))
				{
					result += c;
				}
				else
				{
					writer.str({});
					writer.clear();
					// At first, we need to get rid of possible sign-extension so cast to uint8_t and then cast to integer type
					writer << std::setw(2) << std::setfill('0') << std::hex << static_cast<std::uint32_t>(c);
					result += "\\x" + writer.str();
				}
				break;
		}
	}

	return result;
}

bool endsWith(const std::string& str, const std::string& withWhat)
{
	return (str.length() >= withWhat.length()) &&
		(str.compare(str.length() - withWhat.length(), withWhat.length(), withWhat) == 0);
}

bool endsWith(const std::string& str, char withWhat)
{
	return !str.empty() && str.back() == withWhat;
}

std::string trim(std::string str)
{
	// Based on
	// http://www.codeproject.com/Articles/10880/A-trim-implementation-for-std-string
	const std::string toTrim = " \n\r\t\v";
	std::string::size_type pos = str.find_last_not_of(toTrim);
	if (pos != std::string::npos)
	{
		str.erase(pos + 1);
		pos = str.find_first_not_of(toTrim);
		if (pos != std::string::npos)
			str.erase(0, pos);
	}
	else
	{
		str.erase(str.begin(), str.end());
	}

	return str;
}

}
