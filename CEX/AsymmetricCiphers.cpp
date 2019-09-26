#include "AsymmetricCiphers.h"

NAMESPACE_ENUMERATION

std::string AsymmetricCipherConvert::ToName(AsymmetricCiphers Enumeral)
{
	return AsymmetricPrimitiveConvert::ToName(static_cast<AsymmetricPrimitives>(Enumeral));
}

AsymmetricCiphers AsymmetricCipherConvert::FromName(std::string &Name)
{
	return static_cast<AsymmetricCiphers>(AsymmetricPrimitiveConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND