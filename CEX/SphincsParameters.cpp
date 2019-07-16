#include "SphincsParameters.h"

NAMESPACE_ENUMERATION

std::string SphincsParameterConvert::ToName(SphincsParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

SphincsParameters SphincsParameterConvert::FromName(std::string &Name)
{
	return static_cast<SphincsParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND