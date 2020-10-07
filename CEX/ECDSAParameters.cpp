#include "ECDSAParameters.h"

NAMESPACE_ENUMERATION

std::string ECDSAParameterConvert::ToName(ECDSAParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

ECDSAParameters ECDSAParameterConvert::FromName(std::string &Name)
{
	return static_cast<ECDSAParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND