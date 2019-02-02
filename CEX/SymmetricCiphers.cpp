#include "SymmetricCiphers.h"

NAMESPACE_ENUMERATION

std::string SymmetricCipherConvert::ToName(SymmetricCiphers Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case SymmetricCiphers::AES:
			name = std::string("Rijndael");
			break;
		case SymmetricCiphers::Serpent:
			name = std::string("Serpent");
			break;
		case SymmetricCiphers::RHXS256:
			name = std::string("RHXS256");
			break;
		case SymmetricCiphers::RHXS512:
			name = std::string("RHXS512");
			break;
		case SymmetricCiphers::RHXH256:
			name = std::string("RHXH256");
			break;
		case SymmetricCiphers::RHXH512:
			name = std::string("RHXH512");
			break;
		case SymmetricCiphers::RHXS1024:
			name = std::string("RHXS1024");
			break;
		case SymmetricCiphers::SHXH256:
			name = std::string("SHXH256");
			break;
		case SymmetricCiphers::SHXH512:
			name = std::string("SHXH512");
			break;
		case SymmetricCiphers::SHXS256:
			name = std::string("SHXS256");
			break;
		case SymmetricCiphers::SHXS512:
			name = std::string("SHXS512");
			break;
		case SymmetricCiphers::SHXS1024:
			name = std::string("SHXS1024");
			break;
		case SymmetricCiphers::ACS256A:
			name = std::string("ACS256A");
			break;
		case SymmetricCiphers::ACS512A:
			name = std::string("ACS512A");
			break;
		case SymmetricCiphers::ACS256S:
			name = std::string("ACS256S");
			break;
		case SymmetricCiphers::ACS512S:
			name = std::string("ACS512S");
			break;
		case SymmetricCiphers::ACS:
			name = std::string("ACS");
			break;
		case SymmetricCiphers::ChaCha256:
			name = std::string("ChaCha256");
			break;
		case SymmetricCiphers::ChaCha256AE:
			name = std::string("ChaCha256AE");
			break;
		case SymmetricCiphers::ChaCha512:
			name = std::string("ChaCha512");
			break;
		case SymmetricCiphers::ChaCha512AE:
			name = std::string("ChaCha512AE");
			break;
		case SymmetricCiphers::Threefish256:
			name = std::string("Threefish256");
			break;
		case SymmetricCiphers::Threefish256AE:
			name = std::string("Threefish256AE");
			break;
		case SymmetricCiphers::Threefish512:
			name = std::string("Threefish512");
			break;
		case SymmetricCiphers::Threefish512AE:
			name = std::string("Threefish512AE");
			break;
		case SymmetricCiphers::Threefish1024:
			name = std::string("Threefish1024");
			break;
		case SymmetricCiphers::Threefish1024AE:
			name = std::string("Threefish1024AE");
			break;
		default:
			name = std::string("None");
			break;
	}

	return name;
}

SymmetricCiphers SymmetricCipherConvert::FromName(std::string &Name)
{
	SymmetricCiphers tname;

	if (Name == std::string("Rijndael"))
	{
		tname = SymmetricCiphers::AES;
	}
	else if (Name == std::string("Serpent"))
	{
		tname = SymmetricCiphers::Serpent;
	}
	else if (Name == std::string("RHXS256"))
	{
		tname = SymmetricCiphers::RHXS256;
	}
	else if (Name == std::string("RHXS512"))
	{
		tname = SymmetricCiphers::RHXS512;
	}
	else if (Name == std::string("RHX"))
	{
		tname = SymmetricCiphers::AES;
	}
	else if (Name == std::string("RHXH256"))
	{
		tname = SymmetricCiphers::RHXH256;
	}
	else if (Name == std::string("RHXH512"))
	{
		tname = SymmetricCiphers::RHXH512;
	}
	else if (Name == std::string("RHXS256"))
	{
		tname = SymmetricCiphers::RHXS256;
	}
	else if (Name == std::string("RHXS512"))
	{
		tname = SymmetricCiphers::RHXS512;
	}
	else if (Name == std::string("RHXS1024"))
	{
		tname = SymmetricCiphers::RHXS1024;
	}
	else if (Name == std::string("SHXH256"))
	{
		tname = SymmetricCiphers::SHXH256;
	}
	else if (Name == std::string("SHXH512"))
	{
		tname = SymmetricCiphers::SHXH512;
	}
	else if (Name == std::string("SHXS256"))
	{
		tname = SymmetricCiphers::SHXS256;
	}
	else if (Name == std::string("SHXS512"))
	{
		tname = SymmetricCiphers::SHXS512;
	}
	else if (Name == std::string("SHXS1024"))
	{
		tname = SymmetricCiphers::SHXS1024;
	}
	else if (Name == std::string("ACS256A"))
	{
		tname = SymmetricCiphers::ACS256A;
	}
	else if (Name == std::string("ACS512A"))
	{
		tname = SymmetricCiphers::ACS512A;
	}
	else if (Name == std::string("ACS256S"))
	{
		tname = SymmetricCiphers::ACS256S;
	}
	else if (Name == std::string("ACS512S"))
	{
		tname = SymmetricCiphers::ACS512S;
	}
	else if (Name == std::string("ACS"))
	{
		tname = SymmetricCiphers::ACS;
	}
	else if (Name == std::string("ChaCha256"))
	{
		tname = SymmetricCiphers::ChaCha256;
	}
	else if (Name == std::string("ChaCha256AE"))
	{
		tname = SymmetricCiphers::ChaCha256AE;
	}
	else if (Name == std::string("ChaCha512"))
	{
		tname = SymmetricCiphers::ChaCha512;
	}
	else if (Name == std::string("ChaCha512AE"))
	{
		tname = SymmetricCiphers::ChaCha512AE;
	}
	else if (Name == std::string("Threefish256"))
	{
		tname = SymmetricCiphers::Threefish256;
	}
	else if (Name == std::string("Threefish256AE"))
	{
		tname = SymmetricCiphers::Threefish256AE;
	}
	else if (Name == std::string("Threefish512"))
	{
		tname = SymmetricCiphers::Threefish512;
	}
	else if (Name == std::string("Threefish512AE"))
	{
		tname = SymmetricCiphers::Threefish512AE;
	}
	else if (Name == std::string("Threefish1024"))
	{
		tname = SymmetricCiphers::Threefish1024;
	}
	else if (Name == std::string("Threefish1024AE"))
	{
		tname = SymmetricCiphers::Threefish1024AE;
	}
	else
	{
		tname = SymmetricCiphers::None;
	}

	return tname;
}


NAMESPACE_ENUMERATIONEND