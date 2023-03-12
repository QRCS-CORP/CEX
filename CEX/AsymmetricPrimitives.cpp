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
		case AsymmetricPrimitives::ECDH:
			name = std::string("ECDH");
			break;
		case AsymmetricPrimitives::ECDSA:
			name = std::string("ECDSA");
			break;
		case AsymmetricPrimitives::Kyber:
			name = std::string("Kyber");
			break;
		case AsymmetricPrimitives::McEliece:
			name = std::string("McEliece");
			break;
		case AsymmetricPrimitives::SphincsPlus:
			name = std::string("SphincsPlus");
			break;
		case AsymmetricPrimitives::XMSS:
			name = std::string("XMSS");
			break;
		case AsymmetricPrimitives::XMSSMT:
			name = std::string("XMSSMT");
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
	else if (Name == std::string("ECDH"))
	{
		tname = AsymmetricPrimitives::ECDH;
	}
	else if (Name == std::string("ECDSA"))
	{
		tname = AsymmetricPrimitives::ECDSA;
	}
	else if (Name == std::string("Kyber"))
	{
		tname = AsymmetricPrimitives::Kyber;
	}
	else if (Name == std::string("McEliece"))
	{
		tname = AsymmetricPrimitives::McEliece;
	}	
	else if (Name == std::string("SphincsPlus"))
	{
		tname = AsymmetricPrimitives::SphincsPlus;
	}
	else if (Name == std::string("XMSS"))
	{
		tname = AsymmetricPrimitives::XMSS;
	}
	else if (Name == std::string("XMSSMT"))
	{
		tname = AsymmetricPrimitives::XMSSMT;
	}
	else
	{
		tname = AsymmetricPrimitives::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND