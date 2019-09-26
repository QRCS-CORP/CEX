#include "KyberParameters.h"

NAMESPACE_ENUMERATION

std::string KyberParameterConvert::ToName(KyberParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

KyberParameters KyberParameterConvert::FromName(std::string &Name)
{
	return static_cast<KyberParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND