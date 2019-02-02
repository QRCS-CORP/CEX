#include "Drbgs.h"

NAMESPACE_ENUMERATION

std::string DrbgConvert::ToName(Drbgs Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case Drbgs::BCG:
			name = std::string("BCG");
			break;
		case Drbgs::CSG:
			name = std::string("CSG");
			break;
		case Drbgs::HCG:
			name = std::string("HCG");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

Drbgs DrbgConvert::FromName(std::string &Name)
{
	Drbgs tname;

	if (Name == std::string("BCG"))
	{
		tname = Drbgs::BCG;
	}
	else if (Name == std::string("CSG"))
	{
		tname = Drbgs::CSG;
	}
	else if (Name == std::string("HCG"))
	{
		tname = Drbgs::HCG;
	}
	else
	{
		tname = Drbgs::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND