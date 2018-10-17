#include "CryptoCipherModeException.h"

NAMESPACE_EXCEPTION

CryptoCipherModeException::CryptoCipherModeException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoCipherModeException::CryptoCipherModeException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoCipherModeException::CryptoCipherModeException(const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	m_details(""),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoCipherModeException::CryptoCipherModeException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoCipherModeException::CryptoCipherModeException(const std::string &Origin, const std::string &Message, const std::string &Detail, ErrorCodes ErrorCode)
	:
	m_details(Detail),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoCipherModeException::~CryptoCipherModeException()
{
	m_details.clear();
	m_error = ErrorCodes::None;
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoCipherModeException::Details()
{
	return m_details;
}

ErrorCodes &CryptoCipherModeException::ErrorCode()
{
	return m_error;
}

std::string &CryptoCipherModeException::Message() 
{ 
	return m_message; 
}

std::string &CryptoCipherModeException::Origin() 
{ 
	return m_origin; 
}

NAMESPACE_EXCEPTIONEND
