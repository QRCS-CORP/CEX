#include "NewHopeParameters.h"

NAMESPACE_ENUMERATION

std::string NewHopeParameterConvert::ToName(NewHopeParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

NewHopeParameters NewHopeParameterConvert::FromName(std::string &Name)
{
	return static_cast<NewHopeParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND