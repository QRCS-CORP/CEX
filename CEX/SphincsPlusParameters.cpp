#include "SphincsPlusParameters.h"

NAMESPACE_ENUMERATION

std::string SphincsPlusParameterConvert::ToName(SphincsPlusParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

SphincsPlusParameters SphincsPlusParameterConvert::FromName(std::string &Name)
{
	return static_cast<SphincsPlusParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND