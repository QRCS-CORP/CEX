#include "CryptoMacException.h"

NAMESPACE_EXCEPTION

CryptoMacException::CryptoMacException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoMacException::CryptoMacException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoMacException::CryptoMacException(const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	m_details(""),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoMacException::CryptoMacException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoMacException::CryptoMacException(const std::string &Origin, const std::string &Message, const std::string &Detail, ErrorCodes ErrorCode)
	:
	m_details(Detail),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoMacException::~CryptoMacException()
{
	m_details.clear();
	m_error = ErrorCodes::None;
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoMacException::Details()
{
	return m_details;
}

ErrorCodes &CryptoMacException::ErrorCode()
{
	return m_error;
}

std::string &CryptoMacException::Message()
{ 
	return m_message;
}

std::string &CryptoMacException::Origin() 
{ 
	return m_origin; 
}

NAMESPACE_EXCEPTIONEND
