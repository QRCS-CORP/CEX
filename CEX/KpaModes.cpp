#include "KpaModes.h"

NAMESPACE_ENUMERATION

std::string KbaModeConvert::ToName(KpaModes Enumeral)
{
	return MacConvert::ToName(static_cast<Macs>(Enumeral));
}

KpaModes KbaModeConvert::FromName(std::string &Name)
{
	return static_cast<KpaModes>(MacConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND