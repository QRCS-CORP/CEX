#include "NTRUPrimeParameters.h"

NAMESPACE_ENUMERATION

std::string NTRUPrimeParameterConvert::ToName(NTRUPrimeParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

NTRUPrimeParameters NTRUPrimeParameterConvert::FromName(std::string &Name)
{
	return static_cast<NTRUPrimeParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND