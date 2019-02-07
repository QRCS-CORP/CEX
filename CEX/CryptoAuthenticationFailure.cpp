#include "CryptoAuthenticationFailure.h"

NAMESPACE_EXCEPTION

CryptoAuthenticationFailure::CryptoAuthenticationFailure(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoAuthenticationFailure::Enumeral()
{
	return ExceptionTypes::CryptoAuthenticationFailure;
}

const std::string CryptoAuthenticationFailure::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND
