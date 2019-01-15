#include "CryptoGeneratorException.h"

NAMESPACE_EXCEPTION

CryptoGeneratorException::CryptoGeneratorException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoGeneratorException::Enumeral()
{
	return ExceptionTypes::CryptoGeneratorException;
}

NAMESPACE_EXCEPTIONEND
