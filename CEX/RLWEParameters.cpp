#include "RLWEParameters.h"

NAMESPACE_ENUMERATION

std::string RLWEParameterConvert::ToName(RLWEParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricTransforms>(Enumeral));
}

RLWEParameters RLWEParameterConvert::FromName(std::string &Name)
{
	return static_cast<RLWEParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND