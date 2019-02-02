#include "ThreefishModes.h"

NAMESPACE_ENUMERATION

std::string ThreefishModeConvert::ToName(ThreefishModes Enumeral)
{
	return SymmetricCipherConvert::ToName(static_cast<SymmetricCiphers>(Enumeral));
}

ThreefishModes ThreefishModeConvert::FromName(std::string &Name)
{
	return static_cast<ThreefishModes>(SymmetricCipherConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND