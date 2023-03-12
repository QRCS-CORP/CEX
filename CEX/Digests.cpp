#include "Digests.h"

NAMESPACE_ENUMERATION

std::string DigestConvert::ToName(Digests Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case CEX::Enumeration::Digests::Blake256:
			name = std::string("Blake256");
			break;
		case CEX::Enumeration::Digests::Blake512:
			name = std::string("Blake512");
			break;
		case CEX::Enumeration::Digests::SHA3256:
			name = std::string("SHA3256");
			break;
		case CEX::Enumeration::Digests::SHA3512:
			name = std::string("SHA3512");
			break;
		case CEX::Enumeration::Digests::SHA2256:
			name = std::string("SHA2256");
			break;
		case CEX::Enumeration::Digests::SHA2512:
			name = std::string("SHA2512");
			break;
		case CEX::Enumeration::Digests::SHAKE128:
			name = std::string("SHAKE128");
			break;
		case CEX::Enumeration::Digests::SHAKE256:
			name = std::string("SHAKE256");
			break;
		case CEX::Enumeration::Digests::SHAKE512:
			name = std::string("SHAKE512");
			break;
		case CEX::Enumeration::Digests::Skein256:
			name = std::string("Skein256");
			break;
		case CEX::Enumeration::Digests::Skein512:
			name = std::string("Skein512");
			break;
		case CEX::Enumeration::Digests::Skein1024:
			name = std::string("Skein1024");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

Digests DigestConvert::FromName(std::string &Name)
{
	Digests tname;

	if (Name == std::string("Blake256"))
	{
		tname = Digests::Blake256;
	}
	else if (Name == std::string("Blake512"))
	{
		tname = Digests::Blake512;
	}
	else if (Name == std::string("SHA3256"))
	{
		tname = Digests::SHA3256;
	}
	else if (Name == std::string("SHA3512"))
	{
		tname = Digests::SHA3512;
	}
	else if (Name == std::string("SHA2256"))
	{
		tname = Digests::SHA2256;
	}
	else if (Name == std::string("SHA2512"))
	{
		tname = Digests::SHA2512;
	}
	else if (Name == std::string("SHAKE128"))
	{
		tname = Digests::SHAKE128;
	}
	else if (Name == std::string("SHAKE256"))
	{
		tname = Digests::SHAKE256;
	}
	else if (Name == std::string("SHAKE512"))
	{
		tname = Digests::SHAKE512;
	}
	else if (Name == std::string("Skein256"))
	{
		tname = Digests::Skein256;
	}
	else if (Name == std::string("Skein512"))
	{
		tname = Digests::Skein512;
	}
	else if (Name == std::string("Skein1024"))
	{
		tname = Digests::Skein1024;
	}
	else
	{
		tname = Digests::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND