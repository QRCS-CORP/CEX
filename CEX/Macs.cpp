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
		case Macs::CMACAHXS256:
			name = std::string("CMACAHXS256");
			break;
		case Macs::CMACAHXS512:
			name = std::string("CMACAHXS512");
			break;
		case Macs::GMAC:
			name = std::string("GMAC");
			break;
		case Macs::GMACAHXS256:
			name = std::string("GMACAHXS256");
			break;
		case Macs::GMACAHXS512:
			name = std::string("GMACAHXS512");
			break;
		case Macs::HMACSHA256:
			name = std::string("HMACSHA256");
			break;
		case Macs::HMACSHA512:
			name = std::string("HMACSHA512");
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
	else if (Name == std::string("CMACAHXS256"))
	{
		tname = Macs::CMACAHXS256;
	}
	else if (Name == std::string("CMACAHXS512"))
	{
		tname = Macs::CMACAHXS512;
	}
	else if (Name == std::string("GMAC"))
	{
		tname = Macs::GMAC;
	}
	else if (Name == std::string("GMACAHXS256"))
	{
		tname = Macs::GMACAHXS256;
	}
	else if (Name == std::string("GMACAHXS512"))
	{
		tname = Macs::GMACAHXS512;
	}
	else if (Name == std::string("HMACSHA256"))
	{
		tname = Macs::HMACSHA256;
	}
	else if (Name == std::string("HMACSHA512"))
	{
		tname = Macs::HMACSHA512;
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