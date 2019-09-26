#include "AsymmetricPrimitives.h"

NAMESPACE_ENUMERATION

std::string AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case AsymmetricPrimitives::Dilithium:
			name = std::string("Dilithium");
			break;
		case AsymmetricPrimitives::McEliece:
			name = std::string("McEliece");
			break;
		case AsymmetricPrimitives::Kyber:
			name = std::string("Kyber");
			break;
		case AsymmetricPrimitives::NTRUPrime:
			name = std::string("NTRUPrime");
			break;
		case AsymmetricPrimitives::NewHope:
			name = std::string("NewHope");
			break;
		case AsymmetricPrimitives::SphincsPlus:
			name = std::string("SphincsPlus");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

AsymmetricPrimitives AsymmetricPrimitiveConvert::FromName(std::string &Name)
{
	AsymmetricPrimitives tname;

	if (Name == std::string("Dilithium"))
	{
		tname = AsymmetricPrimitives::Dilithium;
	}
	else if (Name == std::string("McEliece"))
	{
		tname = AsymmetricPrimitives::McEliece;
	}	
	else if (Name == std::string("Kyber"))
	{
		tname = AsymmetricPrimitives::Kyber;
	}
	else if (Name == std::string("NTRUPrime"))
	{
		tname = AsymmetricPrimitives::NTRUPrime;
	}
	else if (Name == std::string("NewHope"))
	{
		tname = AsymmetricPrimitives::NewHope;
	}
	else if (Name == std::string("SphincsPlus"))
	{
		tname = AsymmetricPrimitives::SphincsPlus;
	}
	else
	{
		tname = AsymmetricPrimitives::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND