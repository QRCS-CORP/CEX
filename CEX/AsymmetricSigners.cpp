#include "AsymmetricSigners.h"

NAMESPACE_ENUMERATION

std::string AsymmetricSignerConvert::ToName(AsymmetricSigners Enumeral)
{
	return AsymmetricPrimitiveConvert::ToName(static_cast<AsymmetricPrimitives>(Enumeral));
}

AsymmetricSigners AsymmetricSignerConvert::FromName(std::string &Name)
{
	return static_cast<AsymmetricSigners>(AsymmetricPrimitiveConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND