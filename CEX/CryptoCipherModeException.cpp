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

CryptoCipherModeException::CryptoCipherModeException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoCipherModeException::~CryptoCipherModeException()
{
	m_details.clear();
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoCipherModeException::Details() 
{
	return m_details;
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
