#include "Macs.h"

NAMESPACE_ENUMERATION

std::string MacConvert::ToName(Macs Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case Macs::CMAC:
			name = std::string("CMAC");
			break;
		case Macs::CMACRHXH256:
			name = std::string("CMACRHXH256");
			break;
		case Macs::CMACRHXH512:
			name = std::string("CMACRHXH512");
			break;
		case Macs::CMACRHXS256:
			name = std::string("CMACRHXS256");
			break;
		case Macs::CMACRHXS512:
			name = std::string("CMACRHXS512");
			break;
		case Macs::GMAC:
			name = std::string("GMAC");
			break;
		case Macs::GMACRHXH256:
			name = std::string("GMACRHXH256");
			break;
		case Macs::GMACRHXH512:
			name = std::string("GMACRHXH512");
			break;
		case Macs::GMACRHXS256:
			name = std::string("GMACRHXS256");
			break;
		case Macs::GMACRHXS512:
			name = std::string("GMACRHXS512");
			break;
		case Macs::HMACSHA2256:
			name = std::string("HMACSHA2256");
			break;
		case Macs::HMACSHA2512:
			name = std::string("HMACSHA2512");
			break;
		case Macs::KPA128:
			name = std::string("KPA128");
			break;
		case Macs::KPA256:
			name = std::string("KPA256");
			break;
		case Macs::KPA512:
			name = std::string("KPA512");
			break;
		case Macs::KMAC128:
			name = std::string("KMAC128");
			break;
		case Macs::KMAC256:
			name = std::string("KMAC256");
			break;
		case Macs::KMAC512:
			name = std::string("KMAC512");
			break;
		case Macs::KMAC1024:
			name = std::string("KMAC1024");
			break;
		case Macs::Poly1305:
			name = std::string("Poly1305");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

Macs MacConvert::FromName(std::string &Name)
{
	Macs tname;

	if (Name == std::string("CMAC"))
	{
		tname = Macs::CMAC;
	}
	else if (Name == std::string("CMACRHXH256"))
	{
		tname = Macs::CMACRHXH256;
	}
	else if (Name == std::string("CMACRHXH512"))
	{
		tname = Macs::CMACRHXH512;
	}
	else if (Name == std::string("CMACRHXS256"))
	{
		tname = Macs::CMACRHXS256;
	}
	else if (Name == std::string("CMACRHXS512"))
	{
		tname = Macs::CMACRHXS512;
	}
	else if (Name == std::string("GMAC"))
	{
		tname = Macs::GMAC;
	}
	else if (Name == std::string("GMACRHXH256"))
	{
		tname = Macs::GMACRHXH256;
	}
	else if (Name == std::string("GMACRHXH512"))
	{
		tname = Macs::GMACRHXH512;
	}
	else if (Name == std::string("GMACRHXS256"))
	{
		tname = Macs::GMACRHXS256;
	}
	else if (Name == std::string("GMACRHXS512"))
	{
		tname = Macs::GMACRHXS512;
	}
	else if (Name == std::string("HMACSHA2256"))
	{
		tname = Macs::HMACSHA2256;
	}
	else if (Name == std::string("HMACSHA2512"))
	{
		tname = Macs::HMACSHA2512;
	}
	else if (Name == std::string("KPA128"))
	{
		tname = Macs::KPA128;
	}
	else if (Name == std::string("KPA256"))
	{
		tname = Macs::KPA256;
	}
	else if (Name == std::string("KPA512"))
	{
		tname = Macs::KPA512;
	}
	else if (Name == std::string("KMAC128"))
	{
		tname = Macs::KMAC128;
	}
	else if (Name == std::string("KMAC256"))
	{
		tname = Macs::KMAC256;
	}
	else if (Name == std::string("KMAC512"))
	{
		tname = Macs::KMAC512;
	}
	else if (Name == std::string("KMAC1024"))
	{
		tname = Macs::KMAC1024;
	}
	else if (Name == std::string("Poly1305"))
	{
		tname = Macs::Poly1305;
	}
	else
	{
		tname = Macs::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND