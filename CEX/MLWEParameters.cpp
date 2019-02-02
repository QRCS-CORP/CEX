#include "MLWEParameters.h"

NAMESPACE_ENUMERATION

std::string MLWEParameterConvert::ToName(MLWEParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricTransforms>(Enumeral));
}

MLWEParameters MLWEParameterConvert::FromName(std::string &Name)
{
	return static_cast<MLWEParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND