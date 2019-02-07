#include "CryptoPaddingException.h"

NAMESPACE_EXCEPTION

CryptoPaddingException::CryptoPaddingException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoPaddingException::Enumeral()
{
	return ExceptionTypes::CryptoPaddingException;
}

const std::string CryptoPaddingException::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND
