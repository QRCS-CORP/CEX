#include "CryptoRandomException.h"

NAMESPACE_EXCEPTION

CryptoRandomException::CryptoRandomException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoRandomException::Enumeral()
{
	return ExceptionTypes::CryptoRandomException;
}

const std::string CryptoRandomException::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND
