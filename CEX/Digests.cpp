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
		case CEX::Enumeration::Digests::Keccak256:
			name = std::string("Keccak256");
			break;
		case CEX::Enumeration::Digests::Keccak512:
			name = std::string("Keccak512");
			break;
		case CEX::Enumeration::Digests::Keccak1024:
			name = std::string("Keccak1024");
			break;
		case CEX::Enumeration::Digests::SHA256:
			name = std::string("SHA256");
			break;
		case CEX::Enumeration::Digests::SHA512:
			name = std::string("SHA512");
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
		case CEX::Enumeration::Digests::SHAKE1024:
			name = std::string("SHAKE1024");
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
	else if (Name == std::string("Keccak256"))
	{
		tname = Digests::Keccak256;
	}
	else if (Name == std::string("Keccak512"))
	{
		tname = Digests::Keccak512;
	}
	else if (Name == std::string("Keccak1024"))
	{
		tname = Digests::Keccak1024;
	}
	else if (Name == std::string("SHA256"))
	{
		tname = Digests::SHA256;
	}
	else if (Name == std::string("SHA512"))
	{
		tname = Digests::SHA512;
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
	else if (Name == std::string("SHAKE1024"))
	{
		tname = Digests::SHAKE1024;
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