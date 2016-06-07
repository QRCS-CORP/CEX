#ifndef _CEXENGINE_CRYPTOMACEXCEPTION_H
#define _CEXENGINE_CRYPTOMACEXCEPTION_H

#include "Common.h"

NAMESPACE_EXCEPTION

/// <summary>
/// Wraps exceptions thrown within Message Authentication Code operations
/// </summary>
struct CryptoMacException : std::exception
{
private:
	std::string m_origin;
	std::string m_message;

public:
	/// <summary>
	/// Get/Set: The message associated with the error
	/// </summary>
	std::string &Message() { return m_message; }

	/// <summary>
	/// Get/Set: The origin of the exception in the format Class
	/// </summary>
	std::string &Origin() { return m_origin; }


	/// <summary>
	/// Exception constructor
	/// </summary>
	///
	/// <param name="Message">A custom message or error data</param>
	explicit CryptoMacException(const std::string &Message)
		:
		m_message(Message)
	{
	}

	/// <summary>
	/// Exception constructor
	/// </summary>
	///
	/// <param name="Origin">The origin of the exception</param>
	/// <param name="Message">A custom message or error data</param>
	CryptoMacException(const std::string &Origin, const std::string &Message) 
		: 
		m_origin(Origin), 
		m_message(Message)
	{
	}
};

NAMESPACE_EXCEPTIONEND
#endif