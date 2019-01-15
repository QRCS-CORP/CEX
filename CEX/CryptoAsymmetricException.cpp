#include "CryptoAsymmetricException.h"

NAMESPACE_EXCEPTION

CryptoAsymmetricException::CryptoAsymmetricException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoAsymmetricException::Enumeral()
{
	return ExceptionTypes::CryptoAsymmetricException;
}

NAMESPACE_EXCEPTIONEND

