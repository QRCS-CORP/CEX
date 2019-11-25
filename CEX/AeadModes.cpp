#include "AeadModes.h"

NAMESPACE_ENUMERATION

std::string AeadModeConvert::ToName(AeadModes Enumeral)
{
	return CipherModeConvert::ToName(static_cast<CipherModes>(Enumeral));
}

AeadModes AeadModeConvert::FromName(std::string &Name)
{
	return static_cast<AeadModes>(CipherModeConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND