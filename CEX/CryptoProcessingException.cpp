#include "CryptoProcessingException.h"

NAMESPACE_EXCEPTION

std::string &CryptoProcessingException::Details() 
{
	return m_details; 
}

std::string &CryptoProcessingException::Message() 
{ 
	return m_message; 
}

std::string &CryptoProcessingException::Origin()
{ 
	return m_origin; 
}

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

CryptoProcessingException::CryptoProcessingException(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

NAMESPACE_EXCEPTIONEND