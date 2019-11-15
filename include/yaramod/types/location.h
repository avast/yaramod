/**
 * @file src/types/location.h
 * @brief Declaration and Implementation of class Location.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

namespace yaramod {

class Location
{
public:
	Location() : Location(1, 0) {}
	Location(std::size_t line, std::size_t column) : _begin(line, column), _end(line, column) {}

	/// @name Modifiing methods
	/// @{
	void addLine(std::size_t count = 1)
	{
		std::swap(_begin, _end);
		_end.first = _begin.first + count; // line
		_end.second = 0; // column
	}

	void addColumn(std::size_t count)
	{
		_begin.first = _end.first;
		_begin.second = _end.second;
		_end.second += count;
	}

	void reset()
	{
		_begin = {1, 0};
		_end = {1, 0};
	}
	/// @}

	/// @name Getters
	/// @{
	std::pair<std::size_t, std::size_t> begin() const { return {_begin.first, _begin.second + 1}; }
	const std::pair<std::size_t, std::size_t>& end() const { return _end; }
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Location& location)
	{
		if (location.begin().second < location.end().second)
			os << location.begin().first << "." << location.begin().second << "-" << location.end().second;
		else
			os << location.begin().first << "." << location.begin().second;
		return os;
	}

private:
	std::pair<std::size_t, std::size_t> _begin; // (line, column)
	std::pair<std::size_t, std::size_t> _end; // (line, column)
};

} //namespace yaramod
