#include "CryptoRandomException.h"

NAMESPACE_EXCEPTION

CryptoRandomException::CryptoRandomException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoRandomException::CryptoRandomException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoRandomException::CryptoRandomException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoRandomException::~CryptoRandomException()
{
	m_details.clear();
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoRandomException::Details()
{ 
	return m_details; 
}

std::string &CryptoRandomException::Message() 
{
	return m_message;
}

std::string &CryptoRandomException::Origin() 
{ 
	return m_origin;
}

NAMESPACE_EXCEPTIONEND
