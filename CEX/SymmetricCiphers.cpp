#include "SymmetricCiphers.h"

NAMESPACE_ENUMERATION

std::string SymmetricCipherConvert::ToName(SymmetricCiphers Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
		case SymmetricCiphers::AES:
			name = std::string("AES");
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
		case SymmetricCiphers::ChaChaP20:
			name = std::string("ChaChaP20");
			break;
		case SymmetricCiphers::CSXR20K256:
			name = std::string("CSXR20K256");
			break;
		case SymmetricCiphers::CSX512:
			name = std::string("CSX512");
			break;
		case SymmetricCiphers::CSXR80K512:
			name = std::string("CSXR80K512");
			break;
		case SymmetricCiphers::RCS:
			name = std::string("RCS");
			break;
		case SymmetricCiphers::RCSK256:
			name = std::string("RCSK256");
			break;
		case SymmetricCiphers::RCSK512:
			name = std::string("RCSK512");
			break;
		case SymmetricCiphers::RCSK1024:
			name = std::string("RCSK1024");
			break;
		case SymmetricCiphers::RWS:
			name = std::string("RWS");
			break;
		case SymmetricCiphers::RWSK256:
			name = std::string("RWSK256");
			break;
		case SymmetricCiphers::RWSK512:
			name = std::string("RWSK512");
			break;
		case SymmetricCiphers::RWSK1024:
			name = std::string("RWSK1024");
			break;
		case SymmetricCiphers::TSX256:
			name = std::string("TSX256");
			break;
		case SymmetricCiphers::TSXR72K256:
			name = std::string("TSXR72K256");
			break;
		case SymmetricCiphers::TSX512:
			name = std::string("TSX512");
			break;
		case SymmetricCiphers::TSX1024:
			name = std::string("TSX1024");
			break;
		case SymmetricCiphers::TSXR120K512:
			name = std::string("TSXR120K512");
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
	else if (Name == std::string("ChaChaP20"))
	{
		tname = SymmetricCiphers::ChaChaP20;
	}
	else if (Name == std::string("CSXR20K256"))
	{
		tname = SymmetricCiphers::CSXR20K256;
	}
	else if (Name == std::string("CSX512"))
	{
		tname = SymmetricCiphers::CSX512;
	}
	else if (Name == std::string("CSXR80K512"))
	{
		tname = SymmetricCiphers::CSXR80K512;
	}
	else if (Name == std::string("RCS"))
	{
		tname = SymmetricCiphers::RCS;
	}
	else if (Name == std::string("RCSK256"))
	{
		tname = SymmetricCiphers::RCSK256;
	}
	else if (Name == std::string("RCSK512"))
	{
		tname = SymmetricCiphers::RCSK512;
	}
	else if (Name == std::string("RCSK1024"))
	{
		tname = SymmetricCiphers::RCSK1024;
	}
	else if (Name == std::string("RWS"))
	{
		tname = SymmetricCiphers::RWS;
	}
	else if (Name == std::string("RWSK256"))
	{
		tname = SymmetricCiphers::RWSK256;
	}
	else if (Name == std::string("RWSK512"))
	{
		tname = SymmetricCiphers::RWSK512;
	}
	else if (Name == std::string("RWSK1024"))
	{
		tname = SymmetricCiphers::RWSK1024;
	}
	else if (Name == std::string("TSX256"))
	{
		tname = SymmetricCiphers::TSX256;
	}
	else if (Name == std::string("TSXR72K256"))
	{
		tname = SymmetricCiphers::TSXR72K256;
	}
	else if (Name == std::string("TSX512"))
	{
		tname = SymmetricCiphers::TSX512;
	}
	else if (Name == std::string("TSXR96K512"))
	{
		tname = SymmetricCiphers::TSXR96K512;
	}
	else if (Name == std::string("TSX1024"))
	{
		tname = SymmetricCiphers::TSX1024;
	}
	else if (Name == std::string("TSXR120K512"))
	{
		tname = SymmetricCiphers::TSXR120K512;
	}
	else
	{
		tname = SymmetricCiphers::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND