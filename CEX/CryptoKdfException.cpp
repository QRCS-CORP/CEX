#include "CryptoKdfException.h"

NAMESPACE_EXCEPTION

CryptoKdfException::CryptoKdfException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoKdfException::Enumeral()
{
	return ExceptionTypes::CryptoKdfException;
}

NAMESPACE_EXCEPTIONEND
