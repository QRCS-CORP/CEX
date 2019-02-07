#include "CryptoSymmetricCipherException.h"

NAMESPACE_EXCEPTION

CryptoSymmetricCipherException::CryptoSymmetricCipherException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoSymmetricCipherException::Enumeral()
{
	return ExceptionTypes::CryptoSymmetricCipherException;
}

const std::string CryptoSymmetricCipherException::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND
