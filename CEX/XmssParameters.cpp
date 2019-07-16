#include "XmssParameters.h"

NAMESPACE_ENUMERATION

XmssParameters XmssParameterConvert::FromName(std::string &Name)
{
	return static_cast<XmssParameters>(AsymmetricTransformConvert::FromName(Name));
}

std::string XmssParameterConvert::ToName(XmssParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

NAMESPACE_ENUMERATIONEND