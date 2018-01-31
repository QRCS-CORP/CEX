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

CryptoSymmetricCipherException::CryptoSymmetricCipherException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoSymmetricCipherException::~CryptoSymmetricCipherException()
{
	m_details.clear();
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoSymmetricCipherException::Details()
{ 
	return m_details; 
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
