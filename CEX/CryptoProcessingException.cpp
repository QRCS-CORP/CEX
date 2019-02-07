#include "CryptoProcessingException.h"

NAMESPACE_EXCEPTION

CryptoProcessingException::CryptoProcessingException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoProcessingException::Enumeral()
{
	return ExceptionTypes::CryptoProcessingException;
}

const std::string CryptoProcessingException::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND
