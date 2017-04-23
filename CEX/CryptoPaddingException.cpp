#include "CryptoPaddingException.h"

NAMESPACE_EXCEPTION

std::string &CryptoPaddingException::Details() 
{ 
	return m_details;
}

std::string &CryptoPaddingException::Message()
{ 
	return m_message;
}

std::string &CryptoPaddingException::Origin() 
{ 
	return m_origin;
}

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

CryptoPaddingException::CryptoPaddingException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

NAMESPACE_EXCEPTIONEND