#include "Providers.h"

NAMESPACE_ENUMERATION

std::string ProviderConvert::ToName(Providers Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case Providers::ACP:
			name = std::string("ACP");
			break;
		case Providers::CJP:
			name = std::string("CJP");
			break;
		case Providers::CSP:
			name = std::string("CSP");
			break;
		case Providers::ECP:
			name = std::string("ECP");
			break;
		case Providers::RDP:
			name = std::string("RDP");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

Providers ProviderConvert::FromName(std::string &Name)
{
	Providers tname;

	if (Name == std::string("ACP"))
	{
		tname = Providers::ACP;
	}
	else if (Name == std::string("CJP"))
	{
		tname = Providers::CJP;
	}
	else if (Name == std::string("CSP"))
	{
		tname = Providers::CSP;
	}
	else if (Name == std::string("ECP"))
	{
		tname = Providers::ECP;
	}
	else if (Name == std::string("RDP"))
	{
		tname = Providers::RDP;
	}
	else
	{
		tname = Providers::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND