#include "KmacModes.h"

NAMESPACE_ENUMERATION

std::string KmacModeConvert::ToName(KmacModes Enumeral)
{
	return MacConvert::ToName(static_cast<Macs>(Enumeral));
}

KmacModes KmacModeConvert::FromName(std::string &Name)
{
	return static_cast<KmacModes>(MacConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND