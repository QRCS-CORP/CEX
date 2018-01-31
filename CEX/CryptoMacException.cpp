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

CryptoMacException::CryptoMacException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoMacException::~CryptoMacException()
{
	m_details.clear();
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoMacException::Details() 
{
	return m_details; 
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
