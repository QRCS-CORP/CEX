#include "McElieceParameters.h"

NAMESPACE_ENUMERATION

std::string McElieceParameterConvert::ToName(McElieceParameters Enumeral)
{
	return AsymmetricTransformConvert::ToName(static_cast<AsymmetricParameters>(Enumeral));
}

McElieceParameters McElieceParameterConvert::FromName(std::string &Name)
{
	return static_cast<McElieceParameters>(AsymmetricTransformConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND