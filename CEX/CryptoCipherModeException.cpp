#include "CryptoCipherModeException.h"

NAMESPACE_EXCEPTION

CryptoCipherModeException::CryptoCipherModeException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoCipherModeException::Enumeral()
{
	return ExceptionTypes::CryptoCipherModeException;
}

NAMESPACE_EXCEPTIONEND
