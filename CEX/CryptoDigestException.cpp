#include "CryptoDigestException.h"

NAMESPACE_EXCEPTION

CryptoDigestException::CryptoDigestException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoDigestException::CryptoDigestException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoDigestException::CryptoDigestException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoDigestException::~CryptoDigestException()
{
	m_details.clear();
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoDigestException::Details()
{ 
	return m_details; 
}

std::string &CryptoDigestException::Message() 
{ 
	return m_message; 
}

std::string &CryptoDigestException::Origin()
{ 
	return m_origin;
}

NAMESPACE_EXCEPTIONEND
