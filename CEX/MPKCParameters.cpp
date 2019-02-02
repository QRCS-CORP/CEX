#include "MPKCParameters.h"

NAMESPACE_ENUMERATION

std::string MPKCParameterConvert::ToName(MPKCParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricTransforms>(Enumeral));
}

MPKCParameters MPKCParameterConvert::FromName(std::string &Name)
{
	return static_cast<MPKCParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND