#include "ShakeModes.h"

NAMESPACE_ENUMERATION

std::string ShakeModeConvert::ToName(ShakeModes Enumeral)
{
	return DigestConvert::ToName(static_cast<Digests>(Enumeral));
}

ShakeModes ShakeModeConvert::FromName(std::string &Name)
{
	return static_cast<ShakeModes>(DigestConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND