/**
 * @file src/parser/location.h
 * @brief Declaration and Implementation of class Location.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <algorithm>
#include <cstdint>
#include <iostream>

namespace yaramod {

class Location
{
public:

	/**
	 * Class representing position (line, column) in the file.
	 */
	struct Position {

		Position(std::size_t line, std::size_t column) : line(line), column(column) {}

		std::size_t getLine() { return line; }
		std::size_t getColumn() { return column; }

		std::size_t line;
		std::size_t column;
	};

	Location() : Location(std::string{}) {}
	Location(const std::string& filePath) : Location(filePath, 1, 0) {}
	Location(const std::string& filePath, std::size_t line, std::size_t column)
		: _filePath(filePath), _begin(line, column), _end(line, column) {}
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
		_begin.line = _end.line;
		_begin.column = _end.column;
		_end.column += count;
	}

	void reset()
	{
		_begin = {1, 0};
		_end = {1, 0};
	}
	/// @}

	/// @name Getters
	/// @{
	bool isUnnamed() const { return _filePath == "[stream]"; }
	const std::string& getFilePath() const { return _filePath; }
	Position begin() const { return {_begin.line, _begin.column + 1}; }
	const Position& end() const { return _end; }
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Location& location)
	{
		if (!location.isUnnamed())
			os << location.getFilePath() << ':';
		os << location.begin().line << '.' << location.begin().column;
		if (location.begin().column < location.end().column)
			os << '-' << location.end().column;
		return os;
	}

private:
	std::string _filePath;
	Position _begin;
	Position _end;
};

} //namespace yaramod
