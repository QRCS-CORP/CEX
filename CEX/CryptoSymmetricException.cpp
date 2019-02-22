#include "CryptoSymmetricException.h"

NAMESPACE_EXCEPTION

CryptoSymmetricException::CryptoSymmetricException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoSymmetricException::Enumeral()
{
	return ExceptionTypes::CryptoSymmetricException;
}

const std::string CryptoSymmetricException::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND
