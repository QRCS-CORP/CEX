#include "AsymmetricEngines.h"

NAMESPACE_ENUMERATION

std::string AsymmetricEngineConvert::ToName(AsymmetricEngines Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case AsymmetricEngines::Dilithium:
			name = std::string("Dilithium");
			break;
		case AsymmetricEngines::McEliece:
			name = std::string("McEliece");
			break;
		case AsymmetricEngines::ModuleLWE:
			name = std::string("ModuleLWE");
			break;
		case AsymmetricEngines::NTRU:
			name = std::string("NTRU");
			break;
		case AsymmetricEngines::RingLWE:
			name = std::string("RingLWE");
			break;
		case AsymmetricEngines::Sphincs:
			name = std::string("Sphincs");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

AsymmetricEngines AsymmetricEngineConvert::FromName(std::string &Name)
{
	AsymmetricEngines tname;

	if (Name == std::string("Dilithium"))
	{
		tname = AsymmetricEngines::Dilithium;
	}
	else if (Name == std::string("McEliece"))
	{
		tname = AsymmetricEngines::McEliece;
	}	
	else if (Name == std::string("ModuleLWE"))
	{
		tname = AsymmetricEngines::ModuleLWE;
	}
	else if (Name == std::string("NTRU"))
	{
		tname = AsymmetricEngines::NTRU;
	}
	else if (Name == std::string("RingLWE"))
	{
		tname = AsymmetricEngines::RingLWE;
	}
	else if (Name == std::string("Sphincs"))
	{
		tname = AsymmetricEngines::Sphincs;
	}
	else
	{
		tname = AsymmetricEngines::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND