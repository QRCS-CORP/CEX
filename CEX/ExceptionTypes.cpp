#include "ExceptionTypes.h"

NAMESPACE_ENUMERATION

std::string ExceptionTypeConvert::ToName(ExceptionTypes Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
	case ExceptionTypes::CryptoAsymmetricException:
		name = std::string("CryptoAsymmetricException");
		break;
	case ExceptionTypes::CryptoAuthenticationFailure:
		name = std::string("CryptoAuthenticationFailure");
		break;
	case ExceptionTypes::CryptoCipherModeException:
		name = std::string("CryptoCipherModeException");
		break;
	case ExceptionTypes::CryptoDigestException:
		name = std::string("CryptoDigestException");
		break;
	case ExceptionTypes::CryptoException:
		name = std::string("CryptoException");
		break;
	case ExceptionTypes::CryptoGeneratorException:
		name = std::string("CryptoGeneratorException");
		break;
	case ExceptionTypes::CryptoKdfException:
		name = std::string("CryptoKdfException");
		break;
	case ExceptionTypes::CryptoMacException:
		name = std::string("CryptoMacException");
		break;
	case ExceptionTypes::CryptoPaddingException:
		name = std::string("CryptoPaddingException");
		break;
	case ExceptionTypes::CryptoProcessingException:
		name = std::string("CryptoProcessingException");
		break;
	case ExceptionTypes::CryptoRandomException:
		name = std::string("CryptoRandomException");
		break;
	case ExceptionTypes::CryptoSymmetricCipherException:
		name = std::string("CryptoSymmetricCipherException");
		break;
	default:
		name = std::string("None");
		break;
	}

	return name;
}

ExceptionTypes ExceptionTypeConvert::FromName(std::string &Name)
{
	ExceptionTypes tname;

	if (Name == std::string("CryptoAsymmetricException"))
	{
		tname = ExceptionTypes::CryptoAsymmetricException;
	}
	else if (Name == std::string("CryptoAuthenticationFailure"))
	{
		tname = ExceptionTypes::CryptoAuthenticationFailure;
	}
	else if (Name == std::string("CryptoCipherModeException"))
	{
		tname = ExceptionTypes::CryptoCipherModeException;
	}
	else if (Name == std::string("CryptoDigestException"))
	{
		tname = ExceptionTypes::CryptoDigestException;
	}
	else if (Name == std::string("CryptoException"))
	{
		tname = ExceptionTypes::CryptoException;
	}
	else if (Name == std::string("CryptoGeneratorException"))
	{
		tname = ExceptionTypes::CryptoGeneratorException;
	}
	else if (Name == std::string("CryptoKdfException"))
	{
		tname = ExceptionTypes::CryptoKdfException;
	}
	else if (Name == std::string("CryptoMacException"))
	{
		tname = ExceptionTypes::CryptoMacException;
	}
	else if (Name == std::string("CryptoPaddingException"))
	{
		tname = ExceptionTypes::CryptoPaddingException;
	}
	else if (Name == std::string("CryptoProcessingException"))
	{
		tname = ExceptionTypes::CryptoProcessingException;
	}
	else if (Name == std::string("CryptoRandomException"))
	{
		tname = ExceptionTypes::CryptoRandomException;
	}
	else if (Name == std::string("CryptoSymmetricCipherException"))
	{
		tname = ExceptionTypes::CryptoSymmetricCipherException;
	}
	else
	{
		tname = ExceptionTypes::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND