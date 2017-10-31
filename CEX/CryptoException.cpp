#include "CryptoException.h"

NAMESPACE_EXCEPTION

CryptoException::CryptoException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoException::CryptoException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoException::CryptoException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoException::~CryptoException()
{
	m_details.clear();
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoException::Details()
{
	return m_details;
}

std::string &CryptoException::Message()
{ 
	return m_message;
}

std::string &CryptoException::Origin()
{
	return m_origin;
}

NAMESPACE_EXCEPTIONEND