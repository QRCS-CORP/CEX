#include "CryptoNetworkingException.h"

NAMESPACE_EXCEPTION

CryptoNetworkingException::CryptoNetworkingException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoNetworkingException::Enumeral()
{
	return ExceptionTypes::CryptoAsymmetricException;
}

const std::string CryptoNetworkingException::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND
