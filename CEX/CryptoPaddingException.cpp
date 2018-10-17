#include "CryptoPaddingException.h"

NAMESPACE_EXCEPTION

CryptoPaddingException::CryptoPaddingException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoPaddingException::CryptoPaddingException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoPaddingException::CryptoPaddingException(const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	m_details(""),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoPaddingException::CryptoPaddingException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoPaddingException::CryptoPaddingException(const std::string &Origin, const std::string &Message, const std::string &Detail, ErrorCodes ErrorCode)
	:
	m_details(Detail),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoPaddingException::~CryptoPaddingException()
{
	m_details.clear();
	m_error = ErrorCodes::None;
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoPaddingException::Details()
{
	return m_details;
}

ErrorCodes &CryptoPaddingException::ErrorCode()
{
	return m_error;
}

std::string &CryptoPaddingException::Message()
{ 
	return m_message;
}

std::string &CryptoPaddingException::Origin() 
{ 
	return m_origin;
}

NAMESPACE_EXCEPTIONEND
