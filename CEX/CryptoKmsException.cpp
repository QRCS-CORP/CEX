#include "CryptoKmsException.h"

NAMESPACE_EXCEPTION

CryptoKmsException::CryptoKmsException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoKmsException::Enumeral()
{
	return ExceptionTypes::CryptoKmsException; //-V2571
}

const std::string CryptoKmsException::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND
