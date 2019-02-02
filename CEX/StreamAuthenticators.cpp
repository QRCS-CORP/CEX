#include "StreamAuthenticators.h"

NAMESPACE_ENUMERATION

std::string StreamAuthenticatorConvert::ToName(StreamAuthenticators Enumeral)
{
	return MacConvert::ToName(static_cast<Macs>(Enumeral));
}

StreamAuthenticators StreamAuthenticatorConvert::FromName(std::string &Name)
{
	return static_cast<StreamAuthenticators>(MacConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND