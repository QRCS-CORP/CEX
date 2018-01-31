#include "CryptoGeneratorException.h"

NAMESPACE_EXCEPTION

CryptoGeneratorException::CryptoGeneratorException(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoGeneratorException::CryptoGeneratorException(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoGeneratorException::CryptoGeneratorException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoGeneratorException::~CryptoGeneratorException()
{
	m_details.clear();
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoGeneratorException::Details()
{ 
	return m_details; 
}

std::string &CryptoGeneratorException::Message() 
{ 
	return m_message; 
}

std::string &CryptoGeneratorException::Origin()
{ 
	return m_origin;
}

NAMESPACE_EXCEPTIONEND
