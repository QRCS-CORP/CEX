#include "DilithiumParameters.h"

NAMESPACE_ENUMERATION

std::string DilithiumParameterConvert::ToName(DilithiumParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

DilithiumParameters DilithiumParameterConvert::FromName(std::string &Name)
{
	return static_cast<DilithiumParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND