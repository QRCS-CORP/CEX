#include "RainbowParameters.h"

NAMESPACE_ENUMERATION

std::string RainbowParameterConvert::ToName(RainbowParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

RainbowParameters RainbowParameterConvert::FromName(std::string &Name)
{
	return static_cast<RainbowParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND