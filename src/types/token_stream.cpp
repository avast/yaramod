/**
 * @file src/types/token_stream.cpp
 * @brief Implementation of class TokenStream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <sstream>
#include <stack>

#include "yaramod/types/token_stream.h"
#include "yaramod/utils/utils.h"

namespace yaramod {

constexpr unsigned tabulator_length = 8;

TokenIt TokenStream::emplace_back(TokenType type, char value)
{
	_tokens.emplace_back(type, Literal(std::string(1, value)));
	_formatted = false;
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, const Literal& literal)
{
	_tokens.emplace_back(type, literal);
	_formatted = false;
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, Literal&& literal)
{
	_tokens.emplace_back(type, std::move(literal));
	_formatted = false;
	return --_tokens.end();
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, char value)
{
	_tokens.emplace(before, type, Literal(std::string(1, value)));
	auto output = before;
	_formatted = false;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, const Literal& literal)
{
	_tokens.emplace(before, type, literal);
	auto output = before;
	_formatted = false;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, Literal&& literal)
{
	_tokens.emplace(before, type, std::move(literal));
	auto output = before;
	_formatted = false;
	return --output;
}

TokenIt TokenStream::push_back(const Token& t)
{
	_tokens.push_back(t);
	_formatted = false;
	return --_tokens.end();
}

TokenIt TokenStream::push_back(Token&& t)
{
	_tokens.push_back(std::move(t));
	_formatted = false;
	return --_tokens.end();
}

TokenIt TokenStream::insert(TokenIt before, TokenType type, const Literal& literal)
{
	_formatted = false;
	return _tokens.insert(before, Token(type, literal));
}

TokenIt TokenStream::insert(TokenIt before, TokenType type, Literal&& literal)
{
	_formatted = false;
	return _tokens.insert(before, Token(type, std::move(literal)));
}

TokenIt TokenStream::erase(TokenIt element)
{
	_formatted = false;
	return _tokens.erase(element);
}

TokenIt TokenStream::erase(TokenIt first, TokenIt last)
{
	_formatted = false;
	return _tokens.erase(first, last);
}

void TokenStream::moveAppend(TokenStream* donor)
{
	_tokens.splice(_tokens.end(), donor->_tokens);
	_formatted = false;
}

void TokenStream::moveAppend(TokenIt before, TokenStream* donor)
{
	_tokens.splice(before, donor->_tokens);
	_formatted = false;
}

void TokenStream::moveAppend(TokenStream* donor, TokenIt first, TokenIt last)
{
	_tokens.splice(_tokens.end(), donor->_tokens, first, last);
	_formatted = false;
}

void TokenStream::moveAppend(TokenIt before, TokenStream* donor, TokenIt first, TokenIt last)
{
	_tokens.splice(before, donor->_tokens, first, last);
	_formatted = false;
}

void TokenStream::swapTokens(TokenIt local_first, TokenIt local_last, TokenStream* other, TokenIt other_first, TokenIt other_last)
{
	if (this == other)
	{
		bool other_under_local = false;
		if (local_first == other_first && other_last == local_last)
			return;
		// Check that if there is some intersection, it is inclusion local > other.
		bool other_first_inside = false;
		bool other_last_inside = other_last == local_last;
		for (auto it = local_first; it != local_last; ++it)
		{
			if (it == other_first)
				other_first_inside = true;
			else if (it == other_last)
			{
				other_last_inside = true;
				break;
			}
		}
		if (other_first_inside)
		{
			if (!other_last_inside)
			{
				if (other_first == local_first)
				{
					std::stringstream ss;
					ss << "['" << *local_first << "','" << *local_last << "') is under ['" << *other_first << "','" << *other_last << "').";
					throw YaramodError("Error: Cannot swapTokens when " + ss.str());
				}
				else
				{
					std::stringstream ss;
					ss << "['" << *local_first << "','" << *local_last << "') and ['" << *other_first << "','" << *other_last << "') intersect in proper subset of each of them.";
					throw YaramodError("Error: Cannot swapTokens when " + ss.str());
				}
			}
			else
				other_under_local = true;
		}
		else
		{
			bool local_first_inside = false;
			bool local_last_inside = other_last == local_last;
			for (auto it = other_first; it != other_last; ++it)
			{
				if (it == local_first)
					local_first_inside = true;
				else if (it == local_last)
				{
					local_last_inside = true;
					break;
				}
			}
			if (local_first_inside)
			{
				if (local_first != other_first || local_last_inside)
				{
					std::stringstream ss;
					ss << "['" << *local_first << "','" << *local_last << "') is under ['" << *other_first << "','" << *other_last << "').";
					throw YaramodError("Error: Cannot swapTokens when " + ss.str());
				}
				else
					other_under_local = true;
			}
		}
		if (other_under_local)
		{
			erase(local_first, other_first);
			erase(other_last, local_last);
		}
		else //no intersection at all
		{
			if (local_first != other_last)
				_tokens.splice(local_first, other->_tokens, other_first, other_last);
			else
				_tokens.splice(other_first, other->_tokens, local_first, local_last);
			if (local_last != other_first && local_first != other_last)
				other->_tokens.splice(other_last, _tokens, local_first, local_last);
		}
	}
	else // different token streams
	{
		TokenIt other_insert_before = other_last;
		_tokens.splice(local_first, other->_tokens, other_first, other_last);
		other->_tokens.splice(other_insert_before, _tokens, local_first, local_last);
	}
	_formatted = false;
}

TokenIt TokenStream::begin()
{
	return _tokens.begin();
}

TokenIt TokenStream::end()
{
	return _tokens.end();
}

TokenConstIt TokenStream::begin() const
{
	return _tokens.begin();
}

TokenConstIt TokenStream::end() const
{
	return _tokens.end();
}

std::reverse_iterator<TokenIt> TokenStream::rbegin()
{
	return _tokens.rbegin();
}

std::reverse_iterator<TokenIt> TokenStream::rend()
{
	return _tokens.rend();
}

std::reverse_iterator<TokenConstIt> TokenStream::rbegin() const
{
	return _tokens.rbegin();
}

std::reverse_iterator<TokenConstIt> TokenStream::rend() const
{
	return _tokens.rend();
}

std::optional<TokenIt> TokenStream::predecessor(TokenIt it)
{
	if (it == begin())
		return std::nullopt;
	else
		return std::prev(it);
}

std::size_t TokenStream::size() const
{
	return _tokens.size();
}

bool TokenStream::empty() const
{
	return _tokens.empty();
}

TokenIt TokenStream::find(TokenType type)
{
	return find(type, begin(), end());
}

TokenIt TokenStream::find(TokenType type, TokenIt from)
{
	return find(type, from, end());
}

TokenIt TokenStream::find(TokenType type, TokenIt from, TokenIt to)
{
	return std::find_if(from, to, [&type](const Token& t){ return t.getType() == type; });
}

TokenIt TokenStream::find(const std::set<TokenType>& types, TokenIt from, TokenIt to)
{
	return std::find_if(from, to, [&types](const Token& t){ return types.count(t.getType()) != 0; });
}

TokenIt TokenStream::findBackwards(TokenType type)
{
	return findBackwards(type, begin(), end());
}

TokenIt TokenStream::findBackwards(TokenType type, TokenIt to)
{
	return findBackwards(type, begin(), to);
}

TokenIt TokenStream::findBackwards(TokenType type, TokenIt from, TokenIt to)
{
	if (from == to)
		return to;
	for (TokenIt it = to; --it != from;)
	{
		if (it->getType() == type)
			return it;
	}
	if (from->getType() == type)
		return from;
	else
		return to;
}

TokenIt TokenStream::findBackwards(const std::set<TokenType>& types, TokenIt from, TokenIt to)
{
	if (from == to)
		return to;
	for (TokenIt it = to; --it != from;)
	{
		if (types.count(it->getType()) != 0)
			return it;
	}
	if (types.count(from->getType()) != 0)
		return from;
	else
		return to;
}

std::vector<std::string> TokenStream::getTokensAsText() const
{
	std::vector<std::string> output;
	for (auto t : _tokens)
		output.push_back(t.getPureText());
	return output;
}

void TokenStream::clear()
{
	_tokens.clear();
	_formatted = false;
}


class LeftBracketEntry {
public:
	LeftBracketEntry(std::size_t line, std::size_t tabulator, bool put_new_lines) : _put_new_lines(put_new_lines), _tabulator(tabulator), _line(line) {}

	std::size_t getLine() const { return _line; }
	std::size_t getTabulator() const { return _tabulator; }
	bool putNewLines() const { return _put_new_lines; }
private:
	bool _put_new_lines; // set if this bracket requires new lines in its sector.
	std::size_t _tabulator; // the level of indentation inside of the bracket's sector.
	std::size_t _line; // Which line is the bracket on.
};


class BracketStack {
public:
	void addLeftBracket(std::size_t line, bool put_new_lines)
	{

		if (_brackets.empty())
			_brackets.emplace_back(line, 1, put_new_lines);
		else
		{
			const auto& previous = _brackets.back();
			std::size_t tabulator = previous.getTabulator();
			if (line != previous.getLine())
				++tabulator;
			_brackets.emplace_back(line, tabulator, put_new_lines);
		}
	}

	void addRightBracket()
	{
		assert(!_brackets.empty());
		_brackets.pop_back();
	}

	/// @name Observe methods
	/// @{
	bool putNewlineInCurrentSector() const
	{
		if (_brackets.empty())
			return false;
		return _brackets.back().putNewLines();
	}

	std::string getTabulators() const
	{
		if (_brackets.empty())
			return std::string{};
		return std::string(_brackets.back().getTabulator(), '\t');
	}
	/// @}

private:
	std::vector<LeftBracketEntry> _brackets;
};


bool TokenStream::determineNewlineSectors()
{
	std::stack<TokenIt> leftBrackets;
	std::size_t lineCounter = 0;
	std::size_t doubleLineCounter = 0;
	bool wasLine = false;
	for (auto it = begin(); it != end();)
	{
		auto current = it->getType();
		if (current == TokenType::LP || current == TokenType::LP_ENUMERATION || current == TokenType::LSQB_ENUMERATION || current == TokenType::HEX_JUMP_LEFT_BRACKET || current == TokenType::REGEXP_START_SLASH || current == TokenType::HEX_START_BRACKET || current == TokenType::LP_WITH_SPACE_AFTER || current == TokenType::LP_WITH_SPACES)
			leftBrackets.push(it);
		else if (current == TokenType::RP || current == TokenType::RP_ENUMERATION || current == TokenType::RSQB_ENUMERATION || current == TokenType::HEX_JUMP_RIGHT_BRACKET || current == TokenType::REGEXP_END_SLASH || current == TokenType::HEX_END_BRACKET || current == TokenType::RP_WITH_SPACE_BEFORE || current == TokenType::RP_WITH_SPACES)
		{
			if (leftBrackets.top()->getFlag()) // the '(' corresponding to the current ')' has new-line sector. Therefore we set this token flag too.
				it->setFlag(true);
			leftBrackets.pop();
		}
		else if (!leftBrackets.empty() && (current == TokenType::NEW_LINE || current == TokenType::OR || current == TokenType::AND))
			leftBrackets.top()->setFlag(true);

		// Here we count lines and double lines:
		if (current == TokenType::NEW_LINE)
		{
			++lineCounter;
			if (wasLine)
				++doubleLineCounter;
			wasLine = true;
		}
		else
			wasLine = false;

		// Here we move some tokens preceding some and/or conjunction after these conjunctions.
		// We only move comments and newlines.
		// We only move around conjunctions that were on the beginning of a line:
		if ((current == TokenType::AND || current == TokenType::OR) && std::prev(it)->getType() == TokenType::NEW_LINE)
		{
			auto pre_it = std::prev(it);
			++it;
			auto insert_before = it;
			TokenType lastMoved = insert_before->getType();
			// We invalidate iterators but only those pointing to COMMENTs or NEW_LINEs, which are not referenced from outside of TokenStream.
			while (pre_it->getType() == TokenType::NEW_LINE || pre_it->getType() == TokenType::COMMENT || pre_it->getType() == TokenType::ONELINE_COMMENT)
			{
				if (lastMoved == TokenType::NEW_LINE && pre_it->getType() == TokenType::NEW_LINE)
				{
					pre_it = std::prev(erase(pre_it));
				}
				else
				{
					insert_before = _tokens.emplace(insert_before, std::move(*pre_it));
					pre_it = std::prev(erase(pre_it));
					lastMoved = insert_before->getType();
				}
			}
		}
		else
			++it;
	}
	// when more than half of the newlines is "doubled", then all "doubled" newlines are made simple newline.
	return 3 * doubleLineCounter > lineCounter;
}

void TokenStream::removeRedundantDoubleNewlines()
{
	bool inside_rule = false;
	for (auto it = begin(); it != end();)
	{
		auto current = it->getType();
		if(current == TokenType::RULE_BEGIN)
			inside_rule = true;
		if(current == TokenType::RULE_END)
			inside_rule = false;
		auto nextIt = std::next(it);
		if (nextIt == end())
			break;
		auto next = nextIt->getType();
		if (inside_rule && current == TokenType::NEW_LINE && next == TokenType::NEW_LINE)
			erase(nextIt);
		else
			++it;
	}
}

void TokenStream::comment(const std::string& message, bool multiline, const std::string& indent, bool linebreak)
{
	auto insert_before = empty() ? end() : begin();
	commentBeforeToken(message, insert_before, multiline, indent, linebreak);
}

void TokenStream::commentBehind(const std::string& message, bool multiline, const std::string& indent, bool linebreak)
{
	auto insert_before = end();
	while (insert_before != begin())
	{
		auto predecessor = std::prev(insert_before);
		if (predecessor->getType() == TokenType::NEW_LINE)
			--insert_before;
		else
			break;
	}
	commentBeforeToken(message, insert_before, multiline, indent, linebreak);
}

void TokenStream::commentBeforeToken(const std::string& message, TokenIt insert_before, bool multiline, const std::string& indent, bool linebreak)
{
	if (!message.empty())
	{
		std::stringstream ss;
		ss << indent;
		if (multiline)
		{
			ss << "/*";
			if (message.front() != '\n')
				ss << " ";
			for (auto c : message)
			{
				ss << c;
				if (c == '\n')
					ss << indent;
			}
			if (message.back() != '\n')
				ss << " ";
			ss << "*/";
			emplace(insert_before, TokenType::COMMENT, ss.str());
		}
		else
		{
			for (auto item : message)
				if (item == '\n')
					throw YaramodError("Error: one-line comment must not contain \\n.");
			ss << "// " << message;
			emplace(insert_before, TokenType::ONELINE_COMMENT, ss.str());
		}
		// if (insert_before != end() && (linebreak || !multiline))
		if (linebreak)
			emplace(insert_before, TokenType::NEW_LINE, "\n");
	}
}

void TokenStream::addMissingNewLines()
{
	BracketStack brackets;
	std::size_t lineCounter = 0;
	bool comment_after_include = false;
	for (auto it = begin(); it != end(); ++it)
	{
		auto current = it->getType();
		auto nextIt = std::next(it);
		if (nextIt == end())
		{
			if (current != TokenType::NEW_LINE)
				emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
			break;
		}
		auto next = nextIt->getType();
		if (current == TokenType::LP || current == TokenType::LP_ENUMERATION || current == TokenType::LSQB_ENUMERATION ||current == TokenType::HEX_JUMP_LEFT_BRACKET || current == TokenType::REGEXP_START_SLASH || current == TokenType::HEX_START_BRACKET || current == TokenType::LP_WITH_SPACE_AFTER || current == TokenType::LP_WITH_SPACES)
		{
			brackets.addLeftBracket(lineCounter, it->getFlag());
			// ONELINE_COMMENTs are left right behind the left bracket. COMMENTs are put on separate new line.
			if (brackets.putNewlineInCurrentSector() && next != TokenType::NEW_LINE && next != TokenType::ONELINE_COMMENT)
			{
				nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
				next = nextIt->getType();
			}
		}
		if (current == TokenType::INCLUDE_PATH || comment_after_include)
		{
			comment_after_include = false;
			auto nextNextIt = std::next(nextIt);
			auto nextNext = nextNextIt->getType();
			if (nextNextIt == end())
				continue;
			if (next == TokenType::NEW_LINE)
			{
				if (nextNext != TokenType::NEW_LINE && nextNext != TokenType::INCLUDE_DIRECTIVE && nextNext != TokenType::COMMENT && nextNext != TokenType::ONELINE_COMMENT)
				{
					nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
					next = nextIt->getType();
				}
			}
			else if (next == TokenType::COMMENT || next == TokenType::ONELINE_COMMENT)
			{
				comment_after_include = true;
			}
			else
			{
				if (next != TokenType::NEW_LINE && next != TokenType::INCLUDE_DIRECTIVE && next != TokenType::COMMENT && next != TokenType::ONELINE_COMMENT )
					nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
				nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
				next = nextIt->getType();
			}
		}
		if (next == TokenType::RP || next == TokenType::RP_ENUMERATION || next == TokenType::RSQB_ENUMERATION || next == TokenType::HEX_JUMP_RIGHT_BRACKET || next == TokenType::REGEXP_END_SLASH || next == TokenType::HEX_END_BRACKET || next == TokenType::RP_WITH_SPACE_BEFORE || next == TokenType::RP_WITH_SPACES)
		{
			if (brackets.putNewlineInCurrentSector() && current != TokenType::NEW_LINE)
			{
				nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
				next = nextIt->getType();
			}
			else
				brackets.addRightBracket();
		}
		if (current != TokenType::NEW_LINE && (next == TokenType::CONDITION || next == TokenType::STRINGS || next == TokenType::STRING_ID_AFTER_NEWLINE || next == TokenType::VARIABLES || next == TokenType::VARIABLE_KEY || next == TokenType::META || next == TokenType::META_KEY || next == TokenType::RULE_END || next == TokenType::RULE_BEGIN))
		{
			nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
			next = nextIt->getType();
		}
		if ((next == TokenType::RULE || next == TokenType::GLOBAL || next == TokenType::PRIVATE) && it != begin())
		{
			if (current != TokenType::GLOBAL && current != TokenType::PRIVATE)
			{
				if (current != TokenType::NEW_LINE)
				{
					nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
					nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
					next = nextIt->getType();
				}
				else
				{
					auto prev = std::prev(it)->getType();
					if (prev != TokenType::NEW_LINE && prev != TokenType::COMMENT && prev != TokenType::ONELINE_COMMENT)
					{
						nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
						next = nextIt->getType();
					}
				}
			}
		}
		if (next != TokenType::NEW_LINE && (current == TokenType::COLON_BEFORE_NEWLINE || current == TokenType::OR || current == TokenType::AND))
		{
			if (next == TokenType::COMMENT)
			{
				auto nextNextIt = std::next(nextIt);
				if ((nextNextIt != end()) && (nextNextIt->getType() != TokenType::NEW_LINE))
					emplace(nextNextIt, TokenType::NEW_LINE, _new_line_style);
			}
			else if (next != TokenType::ONELINE_COMMENT)
			{
				nextIt = emplace(nextIt, TokenType::NEW_LINE, _new_line_style);
				next = nextIt->getType();
			}
		}
	}
}

void TokenStream::autoformat()
{
	bool redundant = determineNewlineSectors();
	if (redundant)
		removeRedundantDoubleNewlines();
	addMissingNewLines();
	_formatted = true;
}

std::size_t TokenStream::PrintHelper::insertIntoStream(std::stringstream* ss, char what)
{
	columnCounter += 1;
	if (ss)
		*ss << what;
	return columnCounter;
}

std::size_t TokenStream::PrintHelper::insertIntoStream(std::stringstream* ss, const std::string& what, std::size_t length)
{
	if (length != 0)
		columnCounter += length;
	else
		columnCounter += what.length();
	if (ss)
		*ss << what;
	return columnCounter;
}

// NEW_LINE, returns current column
std::size_t TokenStream::PrintHelper::insertIntoStream(std::stringstream* ss, TokenStream* ts, TokenIt what)
{
	std::stringstream tmp;
	tmp << *what;
	const std::string& appendee = tmp.str();
	assert(what->getType() != TokenType::ONELINE_COMMENT);
	auto prevIt = ts->predecessor(what);
	if (what->getType() == TokenType::NEW_LINE)
	{
		if (!commentOnThisLine || (prevIt && (*prevIt)->getType() == TokenType::COLON))
		{
			if (commentPool.size() >= 2)
				for (auto comment : commentPool)
					comment->setIndentation(maximalCommentColumn);
			commentPool.clear();
			maximalCommentColumn = 0;
		}
		++lineCounter;
		commentOnThisLine = false;
		columnCounter = 0;
	}
	else
	{
		columnCounter += appendee.length();
		if (columnCounter > maximalCommentColumn)
			maximalCommentColumn = columnCounter;
	}

	if (ss)
		*ss << appendee;
	return columnCounter;
}

/**
 * Prints comment.
 *
 * @param ts The associated tokenstream used only for predecessor access.
 * @param ss The stream to be filled with the text.
 * @param it The comment.
 * @param currentLineTabs The current level of indentation based obtained from the autoformatter.
 * @param alignComments Set if comments should be aligned.
 * @patam ignoreUserIndent Set whether we want to ignore the additional indentation specified in parameter it.
 *
 * @return columnCounter.
 */
std::size_t TokenStream::PrintHelper::printComment(std::stringstream* ss, TokenStream* ts, TokenIt it, size_t currentLineTabs, bool alignComment, bool ignoreUserIndent)
{
	auto prevIt = ts->predecessor(it);
	auto indentation = it->getIndentation() + 1;

	const std::string& indent = it->getLiteral().getFormattedValue();
	if (ss)
	{
		// Comment at a beginning of a line
		if (!prevIt || (*prevIt)->getType() == TokenType::NEW_LINE)
		{
			if (ignoreUserIndent || indent.length() >= currentLineTabs)
				*ss << std::string(currentLineTabs, '\t');
			else
				*ss << indent;
		}
		else if (alignComment && columnCounter < indentation && (!prevIt || (*prevIt)->getType() != TokenType::COLON))
			*ss << std::string(indentation - columnCounter, ' ');
		*ss << it->getPureText();
	}
	else if (it->getType() == TokenType::ONELINE_COMMENT && (!prevIt || (*prevIt)->getType() != TokenType::COLON))
	{
		commentOnThisLine = true;
		commentPool.push_back(it);
	}

	return columnCounter;
}

std::string TokenStream::getText(bool withIncludes, bool alignComments)
{
	if (!_formatted)
		autoformat();
	PrintHelper helper;
	if (alignComments)
		getTextProcedure(helper, nullptr, withIncludes, alignComments); // First call determines alignment of comments

	std::stringstream os;
	getTextProcedure(helper, &os, withIncludes, alignComments); // Second call constructs the text
	return os.str();
}

/**
 * Iterates through _tokens and determines where to put whitespaces and other characters.
 * If os != nullptr, it is filled with the text.
 * At the end, each comment is assigned it's desired alignment. This happens at the end - to
 * have the comments aligned in the output, this method should be called twice, first time with
 * os == nullptr.
 *
 * @param helper The expression to enclose.
 * @param os The stream to be filled with the text.
 * @param withIncludes Set if includes are also to be included.
 * @param alignComments Set if comments should be aligned.
 */
void TokenStream::getTextProcedure(PrintHelper& helper, std::stringstream* os, bool withIncludes, bool alignComments)
{
	BracketStack brackets;
	size_t current_line_tabs = 0;
	bool inside_rule = false;
	bool inside_hex_string = false;
	bool inside_hex_jump = false;
	bool inside_regexp = false;
	bool inside_enumeration_brackets = false;
	bool inside_string_modifiers = false;
	bool inside_string_modifiers_arguments = false;
	bool inside_condition_section = false;
	bool second_nibble = true;

	for (auto it = begin(); it != end(); ++it)
	{
		auto current = it->getType();

		if (current == TokenType::INCLUDE_DIRECTIVE && withIncludes)
			continue;
		else if (current == TokenType::INCLUDE_PATH)
		{
			assert(it->isIncludeToken());
			if (withIncludes)
			{
				const std::string& text = it->getSubTokenStream()->getText(withIncludes);
				helper.insertIntoStream(os, text);
				continue;
			}
			else
				helper.insertIntoStream(os, this, it);
		}
		else if (current == TokenType::ONELINE_COMMENT || current == TokenType::COMMENT)
		{
			helper.printComment(os, this, it, current_line_tabs, alignComments, inside_condition_section);
		}
		else
			helper.insertIntoStream(os, this, it);

		auto nextIt = std::next(it);
		if (nextIt == end())
			 break;
		auto next = nextIt->getType();
		if (current == TokenType::RULE_BEGIN)
		{
			current_line_tabs = 2;
			inside_rule = true;
		}
		else if (current == TokenType::RULE_END)
		{
			current_line_tabs = 0;
			inside_rule = false;
			inside_condition_section = false;
		}
		else if (current == TokenType::HEX_START_BRACKET)
			inside_hex_string = true;
		else if (current == TokenType::HEX_END_BRACKET)
			inside_hex_string = false;
		else if (current == TokenType::HEX_JUMP_LEFT_BRACKET)
			inside_hex_jump = true;
		else if (current == TokenType::HEX_JUMP_RIGHT_BRACKET)
			inside_hex_jump = false;
		else if (current == TokenType::REGEXP_START_SLASH)
			inside_regexp = true;
		else if (current == TokenType::REGEXP_END_SLASH)
			inside_regexp = false;
		else if (current == TokenType::LP_ENUMERATION)
			inside_enumeration_brackets = true;
		else if (current == TokenType::RP_ENUMERATION)
			inside_enumeration_brackets = false;
		else if (it->isStringModifier())
			inside_string_modifiers = true;

		if (inside_string_modifiers)
		{
			if (next == TokenType::LP)
				inside_string_modifiers_arguments = true;

			if (inside_string_modifiers_arguments && current == TokenType::RP)
				inside_string_modifiers_arguments = false;

			if (!inside_string_modifiers_arguments && !it->isStringModifier())
				inside_string_modifiers = false;
		}

		if (it->isLeftBracket())
		{
			brackets.addLeftBracket(helper.getCurrentLine(), it->getFlag());
			if (it->getFlag())
				++current_line_tabs;
		}
		if (it->isRightBracket())
		{
			brackets.addRightBracket();
		}
		if (current == TokenType::NEW_LINE)
		{
			if (inside_rule && next != TokenType::ONELINE_COMMENT && next != TokenType::COMMENT && next != TokenType::NEW_LINE)
			{
				if (next == TokenType::META
					|| next == TokenType::VARIABLES
					|| next == TokenType::STRINGS
					|| next == TokenType::CONDITION)
				{
					inside_condition_section = next == TokenType::CONDITION;
					helper.insertIntoStream(os, "\t", tabulator_length);
				}
				else if (next != TokenType::RULE_END)
				{
					if (nextIt->isRightBracket() && nextIt->getFlag())
						--current_line_tabs;
					helper.insertIntoStream(os, std::string(current_line_tabs, '\t'), current_line_tabs * tabulator_length);
				}
			}
		}
		else if (inside_hex_string)
		{
			switch(current)
			{
				case TokenType::HEX_NIBBLE:
				case TokenType::HEX_WILDCARD_LOW:
				case TokenType::HEX_WILDCARD_HIGH:
					second_nibble = !second_nibble;
					break;
				case TokenType::HEX_ALT:
				case TokenType::HEX_JUMP_FIXED:
				case TokenType::HEX_JUMP_RIGHT_BRACKET:
				case TokenType::HEX_START_BRACKET:
					second_nibble = true;
					break;
				default:
					break;
			}
			if (!inside_hex_jump && next != TokenType::NEW_LINE)
			{
				if (second_nibble && next != TokenType::COMMA)
					helper.insertIntoStream(os, ' ');
			}
		}
		else if (!inside_regexp && !inside_enumeration_brackets && !inside_string_modifiers_arguments)
		{
			switch(current)
			{
				case TokenType::META:
				case TokenType::VARIABLES:
				case TokenType::STRINGS:
				case TokenType::CONDITION:
				case TokenType::UNARY_MINUS:
				case TokenType::BITWISE_NOT:
				case TokenType::INTEGER_FUNCTION:
				case TokenType::FUNCTION_SYMBOL:
				case TokenType::LSQB:
				case TokenType::DOT:
				case TokenType::FUNCTION_CALL_LP:
					break;
				case TokenType::LP:
					if (next == TokenType::COMMENT || next == TokenType::ONELINE_COMMENT)
						helper.insertIntoStream(os, ' ');
					break;
				default:
					auto nextNextIt = std::next(nextIt);
					switch(next)
					{
						case TokenType::RP:
						case TokenType::RSQB:
						case TokenType::DOT:
						case TokenType::NEW_LINE:
						case TokenType::COMMA:
						case TokenType::LSQB:
						case TokenType::FUNCTION_CALL_LP:
						case TokenType::FUNCTION_CALL_RP:
							break;
						case TokenType::REGEXP_MODIFIERS:
							if (current != TokenType::REGEXP_MODIFIERS)
								break;
							[[fallthrough]];
						default:
							if (next != TokenType::LSQB || (current != TokenType::STRING_OFFSET && current != TokenType::STRING_LENGTH))
							{
								if (next != TokenType::PERCENT || nextNextIt == end() || nextNextIt->getType() != TokenType::OF)
									helper.insertIntoStream(os, ' ');
							}
					}
			}
		}
		else if (inside_enumeration_brackets)
		{
			if ((current != TokenType::LP_ENUMERATION && next != TokenType::RP_ENUMERATION) && (current != TokenType::LSQB_ENUMERATION && next != TokenType::RSQB_ENUMERATION) && current != TokenType::DOT && next != TokenType::COMMA && next != TokenType::DOT && next != TokenType::NEW_LINE)
				helper.insertIntoStream(os, ' ');
		}
		else if (current == TokenType::HEX_ALT_RIGHT_BRACKET || current == TokenType::HEX_ALT_LEFT_BRACKET)
			helper.insertIntoStream(os, ' ');
	}
}

} //namespace yaramod
