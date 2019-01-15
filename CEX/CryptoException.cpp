#include "CryptoException.h"

NAMESPACE_EXCEPTION

CryptoException::CryptoException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	m_error(ErrorCode),
	m_location(Location),
	m_message(Message),
	m_origin(Origin)
{
}

CryptoException::~CryptoException()
{
	m_error = ErrorCodes::None;
	m_location.clear();
	m_message.clear();
	m_origin.clear();
}

//~~~Accessors~~~//

const ErrorCodes CryptoException::ErrorCode()
{
	return m_error;
}

const ExceptionTypes CryptoException::Enumeral()
{
	return ExceptionTypes::CryptoException;
}

const std::string CryptoException::Location()
{
	return m_location;
}

const std::string CryptoException::Message()
{
	return m_message;
}

const std::string CryptoException::Origin()
{
	return m_origin;
}

NAMESPACE_EXCEPTIONEND
