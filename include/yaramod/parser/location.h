/**
 * @file src/parser/location.h
 * @brief Declaration and Implementation of class Location.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>

namespace yaramod {

class Location
{
public:

	/**
	 * Class representing position (line, column) in the file.
	 */
	struct Position {

		Position() : line(1), column(0) {}
		Position(std::size_t line, std::size_t column) : line(line), column(column) {}

		std::size_t getLine() const { return line; }
		std::size_t getColumn() const { return column; }

		std::size_t line;
		std::size_t column;
		friend std::ostream& operator<<(std::ostream& os, const Position& position)
		{
			os << position.getLine() << '.' << position.getColumn();
			return os;
		}
	};

	Location() : Location(std::string{}) {}
	Location(const std::string& filePath) : Location(filePath, 1, 0) {}
	Location(const std::string& filePath, std::size_t line, std::size_t column)
		: _filePath(filePath), _begin(line, column), _end(line, column) {}
	Location(const std::string& filePath, const Position &begin, const Position& end)
		: _filePath(filePath), _begin(begin), _end(end) {}
	Location(const Location&) = default;
	Location(Location&&) noexcept = default;

	Location& operator=(const Location&) = default;
	Location& operator=(Location&&) noexcept = default;

	/// @name Modifying methods
	/// @{
	void addLine(std::size_t count = 1)
	{
		std::swap(_begin, _end);
		_end.line = _begin.line + count; // line
		_end.column = 0; // column
	}

	void addColumn(std::size_t count)
	{
		_begin = _end;
		_end.column += count;
	}

	void reset()
	{
		_begin = {1, 0};
		_end = {1, 0};
	}

	void setBegin(const Position& begin)
	{
		_begin.line = begin.line;
		_begin.column = begin.column - 1;
	}
	/// @}

	/// @name Getters
	/// @{
	bool isUnnamed() const { return _filePath == "[stream]"; }
	/**
	 * Returns the absolute path of a file in which this rule was located.
	 * Returns "[stream]" in case this rule was parsed from input stream and not a file,
	 * or if this file was created with `YaraRuleBuilder`.
	 */
	const std::string& getFilePath() const { return _filePath; }
	Position begin() const { return {_begin.line, _begin.column + 1}; }
	const Position& end() const { return _end; }
	std::string getText() const
	{
		std::ostringstream ss;
		ss << *this;
		return ss.str();
	}
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Location& location)
	{
		if (!location.isUnnamed())
			os << location.getFilePath() << ':';
		os << location.begin();
		if (location.begin().line != location.end().line)
			os << '-' << location.end();
		else if (location.begin().column < location.end().column)
			os << '-' << location.end().column;
		return os;
	}

private:
	std::string _filePath;
	Position _begin;
	Position _end;
};

} //namespace yaramod
