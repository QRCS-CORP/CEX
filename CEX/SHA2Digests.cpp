#include "SHA2Digests.h"

NAMESPACE_ENUMERATION

std::string SHA2DigestConvert::ToName(SHA2Digests Enumeral)
{
	return DigestConvert::ToName(static_cast<Digests>(Enumeral));
}

SHA2Digests SHA2DigestConvert::FromName(std::string &Name)
{
	return static_cast<SHA2Digests>(DigestConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND