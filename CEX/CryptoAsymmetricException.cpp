#include "CryptoAsymmetricException.h"

NAMESPACE_EXCEPTION

CryptoAsymmetricException::CryptoAsymmetricException(const std::string &Message)
	:
	m_details(""),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin("")
{
}

CryptoAsymmetricException::CryptoAsymmetricException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoAsymmetricException::CryptoAsymmetricException(const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	m_details(""),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoAsymmetricException::CryptoAsymmetricException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoAsymmetricException::CryptoAsymmetricException(const std::string &Origin, const std::string &Message, const std::string &Detail, ErrorCodes ErrorCode)
	:
	m_details(Detail),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoAsymmetricException::~CryptoAsymmetricException()
{
	m_details.clear();
	m_error = ErrorCodes::None;
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoAsymmetricException::Details() 
{ 
	return m_details; 
}

ErrorCodes &CryptoAsymmetricException::ErrorCode()
{
	return m_error;
}

std::string &CryptoAsymmetricException::Message() 
{
	return m_message; 
}

std::string &CryptoAsymmetricException::Origin() 
{
	return m_origin; 
}

NAMESPACE_EXCEPTIONEND
