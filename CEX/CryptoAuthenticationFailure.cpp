#include "CryptoAuthenticationFailure.h"

NAMESPACE_EXCEPTION

CryptoAuthenticationFailure::CryptoAuthenticationFailure(const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin("")
{
}

CryptoAuthenticationFailure::CryptoAuthenticationFailure(const std::string &Origin, const std::string &Message)
	:
	m_details(""),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoAuthenticationFailure::CryptoAuthenticationFailure(const std::string &Origin, const std::string &Message, const std::string &Detail)
	:
	m_details(Detail),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoAuthenticationFailure::~CryptoAuthenticationFailure()
{
	m_details.clear();
	m_message.clear();
	m_origin.clear();
}

std::string &CryptoAuthenticationFailure::Details()
{
	return m_details;
}

std::string &CryptoAuthenticationFailure::Message()
{
	return m_message;
}

std::string &CryptoAuthenticationFailure::Origin()
{
	return m_origin;
}

NAMESPACE_EXCEPTIONEND
