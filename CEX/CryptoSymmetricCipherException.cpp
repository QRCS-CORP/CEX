#include "CryptoSymmetricCipherException.h"

NAMESPACE_EXCEPTION

CryptoSymmetricCipherException::CryptoSymmetricCipherException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoSymmetricCipherException::CryptoSymmetricCipherException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoSymmetricCipherException::CryptoSymmetricCipherException(const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	m_details(""),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoSymmetricCipherException::CryptoSymmetricCipherException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoSymmetricCipherException::CryptoSymmetricCipherException(const std::string &Origin, const std::string &Message, const std::string &Detail, ErrorCodes ErrorCode)
	:
	m_details(Detail),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoSymmetricCipherException::~CryptoSymmetricCipherException()
{
	m_details.clear();
	m_error = ErrorCodes::None;
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoSymmetricCipherException::Details()
{
	return m_details;
}

ErrorCodes &CryptoSymmetricCipherException::ErrorCode()
{
	return m_error;
}

std::string &CryptoSymmetricCipherException::Message() 
{
	return m_message; 
}

std::string &CryptoSymmetricCipherException::Origin() 
{ 
	return m_origin;
}

NAMESPACE_EXCEPTIONEND
