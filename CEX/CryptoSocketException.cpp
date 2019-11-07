#include "CryptoSocketException.h"

NAMESPACE_EXCEPTION

CryptoSocketException::CryptoSocketException(const std::string& Location, const std::string& Origin, const std::string& Message, ErrorCodes ErrorCode)
	:
	CryptoException(Location, Origin, Message, ErrorCode)
{
}

const ExceptionTypes CryptoSocketException::Enumeral()
{
	return ExceptionTypes::CryptoAsymmetricException;
}

const std::string CryptoSocketException::Name()
{
	return Enumeration::ExceptionTypeConvert::ToName(Enumeral());
}

NAMESPACE_EXCEPTIONEND

