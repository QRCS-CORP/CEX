#include "CryptoProcessingException.h"

NAMESPACE_EXCEPTION

CryptoProcessingException::CryptoProcessingException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoProcessingException::CryptoProcessingException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoProcessingException::CryptoProcessingException(const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	m_details(""),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoProcessingException::CryptoProcessingException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_error(ErrorCodes::None),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoProcessingException::CryptoProcessingException(const std::string &Origin, const std::string &Message, const std::string &Detail, ErrorCodes ErrorCode)
	:
	m_details(Detail),
	m_error(ErrorCode),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoProcessingException::~CryptoProcessingException()
{
	m_details.clear();
	m_error = ErrorCodes::None;
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoProcessingException::Details()
{
	return m_details;
}

ErrorCodes &CryptoProcessingException::ErrorCode()
{
	return m_error;
}

std::string &CryptoProcessingException::Message() 
{ 
	return m_message; 
}

std::string &CryptoProcessingException::Origin()
{ 
	return m_origin; 
}

NAMESPACE_EXCEPTIONEND
