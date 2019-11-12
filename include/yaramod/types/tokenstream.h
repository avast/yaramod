#pragma once

#include <list>
#include <vector>

#include "yaramod/types/token.h"

namespace yaramod {

class TokenStream
{
public:
	class PrintHelper
	{
	public:
		std::size_t getCurrentLine() const { return lineCounter; }
		const std::vector<TokenIt>& getCommentPool() const { return commentPool; }

		std::size_t insertIntoStream(std::stringstream* ss, char what);
		std::size_t insertIntoStream(std::stringstream* ss, const std::string& what, std::size_t length = 0);
		std::size_t insertIntoStream(std::stringstream* ss, TokenStream* ts, TokenIt what);
		std::size_t printComment(std::stringstream* ss, TokenStream* ts, TokenIt it, bool alignComment);
	private:
		std::size_t lineCounter = 0;
		std::size_t columnCounter = 0;
		bool commentOnThisLine = false;
		std::size_t maximalCommentColumn = 0;
		std::vector<TokenIt> commentPool;
	};

	TokenStream() = default;

	/// @name Insertion methods
	/// @{
	TokenIt emplace_back(TokenType type, char value);
	TokenIt emplace_back(TokenType type, const char* value, const std::optional<std::string>& formatted_value = std::nullopt);
	TokenIt emplace_back(TokenType type, const std::string& value, const std::optional<std::string>& formatted_value = std::nullopt);
	TokenIt emplace_back(TokenType type, std::string&& value, const std::optional<std::string>& formatted_value = std::nullopt);
	TokenIt emplace_back(TokenType type, bool b, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace_back(TokenType type, int i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace_back(TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace_back(TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace_back(TokenType type, double i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace_back(TokenType type, const std::shared_ptr<Symbol>& s, const std::string& symbol_name);
	TokenIt emplace_back(TokenType type, std::shared_ptr<Symbol>&& s, const std::string& symbol_name);
	TokenIt emplace_back(TokenType type, const Literal& literal);
	TokenIt emplace_back(TokenType type, Literal&& literal);
	TokenIt emplace(const TokenIt& before, TokenType type, char value);
	TokenIt emplace(const TokenIt& before, TokenType type, const char* value);
	TokenIt emplace(const TokenIt& before, TokenType type, const std::string& value);
	TokenIt emplace(const TokenIt& before, TokenType type, std::string&& value);
	TokenIt emplace(const TokenIt& before, TokenType type, bool b);
	TokenIt emplace(const TokenIt& before, TokenType type, int i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace(const TokenIt& before, TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace(const TokenIt& before, TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace(const TokenIt& before, TokenType type, const std::shared_ptr<Symbol>& s, const std::string& symbol_name);
	TokenIt emplace(const TokenIt& before, TokenType type, std::shared_ptr<Symbol>&& s, const std::string& symbol_name);
	TokenIt emplace(const TokenIt& before, TokenType type, double i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	TokenIt emplace(const TokenIt& before, TokenType type, const Literal& literal);
	TokenIt emplace(const TokenIt& before, TokenType type, Literal&& literal);
	TokenIt push_back(const Token& t);
	TokenIt push_back(Token&& t);
	TokenIt insert(TokenIt before, TokenType type, const Literal& literal);
	TokenIt insert(TokenIt before, TokenType type, Literal&& literal);
	TokenIt erase(TokenIt element);
	TokenIt erase(TokenIt first, TokenIt last);
	void move_append(TokenStream* donor);
	void move_append(TokenStream* donor, TokenIt before);
	/// @}

	/// @name Iterators
	/// @{
	TokenIt begin();
	TokenIt end();
	TokenConstIt begin() const;
	TokenConstIt end() const;
	TokenItReversed rbegin();
	TokenItReversed rend();
	TokenConstItReversed rbegin() const;
	TokenConstItReversed rend() const;
	/// @}

	/// @name Capacity
	/// @{
	std::size_t size() const;
	bool empty() const;
	/// @}

	/// @name Lookaround methods
	/// @{
	TokenIt find(TokenType type);
	TokenIt find(TokenType type, TokenIt from);
	TokenIt find(TokenType type, TokenIt from, TokenIt to);
	TokenIt findBackwards(TokenType type);
	TokenIt findBackwards(TokenType type, TokenIt to);
	TokenIt findBackwards(TokenType type, TokenIt from, TokenIt to);
	std::optional<TokenIt> predecessor(TokenIt it);
	/// @}

	/// @name Text representation
	/// @{
	friend std::ostream& operator<<(std::ostream& os, TokenStream& ts) { return os << ts.getText(false); }
	std::string getText(bool withIncludes = false, bool alignComments = true);
	std::vector<std::string> getTokensAsText() const;
	/// @}

	/// @name Reseting method
	void clear();
	/// @}
protected:
	void computeCommentAlignment(bool withIncludes);
	void getTextProcedure(PrintHelper& helper, std::stringstream* os, bool withIncludes, bool alignComments);
	void autoformat();
	void determineNewlineSectors();
	void addMissingNewLines();
private:
	std::list< Token > _tokens; ///< All tokens off the rule
	bool formatted = false; ///< The flag is set once autoformat has been called
};

} //namespace yaramod
