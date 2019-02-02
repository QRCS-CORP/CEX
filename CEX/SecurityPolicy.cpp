#include "SecurityPolicy.h"

NAMESPACE_ENUMERATION

std::string SecurityPolicyConvert::ToName(SecurityPolicy Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case CEX::Enumeration::SecurityPolicy::SPL256:
			name = std::string("SPL256");
			break;
		case CEX::Enumeration::SecurityPolicy::SPL256AE:
			name = std::string("SPL256AE");
			break;
		case CEX::Enumeration::SecurityPolicy::SPL512:
			name = std::string("SPL512");
			break;
		case CEX::Enumeration::SecurityPolicy::SPL512AE:
			name = std::string("SPL512AE");
			break;
		case CEX::Enumeration::SecurityPolicy::SPL1024:
			name = std::string("SPL1024");
			break;
		case CEX::Enumeration::SecurityPolicy::SPL1024AE:
			name = std::string("SPL1024AE");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

SecurityPolicy SecurityPolicyConvert::FromName(std::string &Name)
{
	SecurityPolicy tname;

	if (Name == std::string("SPL256"))
	{
		tname = SecurityPolicy::SPL256;
	}
	else if (Name == std::string("SPL256AE"))
	{
		tname = SecurityPolicy::SPL256AE;
	}
	else if (Name == std::string("SPL512"))
	{
		tname = SecurityPolicy::SPL512;
	}
	else if (Name == std::string("SPL512AE"))
	{
		tname = SecurityPolicy::SPL512AE;
	}
	else if (Name == std::string("SPL1024"))
	{
		tname = SecurityPolicy::SPL1024;
	}
	else if (Name == std::string("SPL1024AE"))
	{
		tname = SecurityPolicy::SPL1024AE;
	}
	else
	{
		tname = SecurityPolicy::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND