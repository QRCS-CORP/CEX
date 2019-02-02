#include "NTRUParameters.h"

NAMESPACE_ENUMERATION

std::string NTRUParameterConvert::ToName(NTRUParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricTransforms>(Enumeral));
}

NTRUParameters NTRUParameterConvert::FromName(std::string &Name)
{
	return static_cast<NTRUParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND