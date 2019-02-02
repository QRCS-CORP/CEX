#include "BlockCiphers.h"

NAMESPACE_ENUMERATION

std::string BlockCipherConvert::ToName(BlockCiphers Enumeral)
{
	return SymmetricCipherConvert::ToName(static_cast<SymmetricCiphers>(Enumeral));
}

BlockCiphers BlockCipherConvert::FromName(std::string &Name)
{
	return static_cast<BlockCiphers>(SymmetricCipherConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND