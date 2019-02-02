#include "StreamCiphers.h"

NAMESPACE_ENUMERATION

std::string StreamCipherConvert::ToName(StreamCiphers Enumeral)
{
	return SymmetricCipherConvert::ToName(static_cast<SymmetricCiphers>(Enumeral));
}

StreamCiphers StreamCipherConvert::FromName(std::string &Name)
{
	return static_cast<StreamCiphers>(SymmetricCipherConvert::FromName(Name));
}

NAMESPACE_ENUMERATIONEND