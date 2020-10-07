#include "ECDHParameters.h"

NAMESPACE_ENUMERATION

std::string ECDHParameterConvert::ToName(ECDHParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

ECDHParameters ECDHParameterConvert::FromName(std::string &Name)
{
	return static_cast<ECDHParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND