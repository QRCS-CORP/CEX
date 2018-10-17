#include "CryptoKdfException.h"

NAMESPACE_EXCEPTION

CryptoKdfException::CryptoKdfException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoKdfException::CryptoKdfException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoKdfException::CryptoKdfException(const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	m_details(""),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoKdfException::CryptoKdfException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoKdfException::CryptoKdfException(const std::string &Origin, const std::string &Message, const std::string &Detail, ErrorCodes ErrorCode)
	:
	m_details(Detail),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoKdfException::~CryptoKdfException()
{
	m_details.clear();
	m_error = ErrorCodes::None;
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoKdfException::Details()
{
	return m_details;
}

ErrorCodes &CryptoKdfException::ErrorCode()
{
	return m_error;
}

std::string &CryptoKdfException::Message() 
{
	return m_message; 
}

std::string &CryptoKdfException::Origin() 
{ 
	return m_origin;
}

NAMESPACE_EXCEPTIONEND
