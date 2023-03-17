#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

std::string AsymmetricTransformConvert::ToName(AsymmetricParameters Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
	case AsymmetricParameters::DLTMS1P2544:
		name = std::string("DLTMS1P2544");
		break;
	case AsymmetricParameters::DLTMS3P4016:
		name = std::string("DLTMS3P4016");
		break;
	case AsymmetricParameters::DLTMS5P4880:
		name = std::string("DLTMS5P4880");
		break;
	case AsymmetricParameters::ECDHS1P25519K:
		name = std::string("ECDHS1P25519K");
		break;
	case AsymmetricParameters::ECDHS2P25519S:
		name = std::string("ECDHS2P25519S");
		break;
	case AsymmetricParameters::ECDSAS1P25519K:
		name = std::string("ECDSAS1P25519K");
		break;
	case AsymmetricParameters::ECDSAS2P25519S:
		name = std::string("ECDSAS2P25519S");
		break;
	case AsymmetricParameters::KYBERS3P2400:
		name = std::string("KYBERS3P2400");
		break;
	case AsymmetricParameters::KYBERS5P3168:
		name = std::string("KYBERS5P3168");
		break;
	case AsymmetricParameters::KYBERS6P3936:
		name = std::string("KYBERS6P3936");
		break;
	case AsymmetricParameters::MPKCS3N4608T96:
		name = std::string("MPKCS3N4608T96");
		break;
	case AsymmetricParameters::MPKCS3N6960T119:
		name = std::string("MPKCS3N6960T119");
		break;
	case AsymmetricParameters::MPKCS4N6688T128:
		name = std::string("MPKCS4N6688T128");
		break;
	case AsymmetricParameters::MPKCS5N8192T128:
		name = std::string("MPKCS5N8192T128");
		break;
	case AsymmetricParameters::SPXPS1S128SHAKE:
		name = std::string("SPXPS1S128SHAKE");
		break;
	case AsymmetricParameters::SPXPS3S192SHAKE:
		name = std::string("SPXPS3S192SHAKE");
		break;
	case AsymmetricParameters::SPXPS5S256SHAKE:
		name = std::string("SPXPS5S256SHAKE");
		break;
	case AsymmetricParameters::XMSSSHA2256H10:
		name = std::string("XMSSSHA2256H10");
		break;
	case AsymmetricParameters::XMSSSHA2256H16:
		name = std::string("XMSSSHA2256H16");
		break;
	case AsymmetricParameters::XMSSSHA2256H20:
		name = std::string("XMSSSHA2256H20");
		break;
	case AsymmetricParameters::XMSSSHA2512H10:
		name = std::string("XMSSSHA2512H10");
		break;
	case AsymmetricParameters::XMSSSHA2512H16:
		name = std::string("XMSSSHA2512H16");
		break;
	case AsymmetricParameters::XMSSSHA2512H20:
		name = std::string("XMSSSHA2512H20");
		break;
	case AsymmetricParameters::XMSSSHAKE256H10:
		name = std::string("XMSSSHAKE256H10");
		break;
	case AsymmetricParameters::XMSSSHAKE256H16:
		name = std::string("XMSSSHAKE256H16");
		break;
	case AsymmetricParameters::XMSSSHAKE256H20:
		name = std::string("XMSSSHAKE256H20");
		break;
	case AsymmetricParameters::XMSSSHAKE512H10:
		name = std::string("XMSSSHAKE512H10");
		break;
	case AsymmetricParameters::XMSSSHAKE512H16:
		name = std::string("XMSSSHAKE512H16");
		break;	
	case AsymmetricParameters::XMSSSHAKE512H20:
		name = std::string("XMSSSHAKE512H20");
		break;
	case AsymmetricParameters::XMSSMTSHA2256H20D2:
		name = std::string("XMSSMTSHA2256H20D2");
		break;
	case AsymmetricParameters::XMSSMTSHA2256H40D2:
		name = std::string("XMSSMTSHA2256H40D2");
		break;
	case AsymmetricParameters::XMSSMTSHA2256H20D4:
		name = std::string("XMSSMTSHA2256H20D4");
		break;
	case AsymmetricParameters::XMSSMTSHA2256H40D4:
		name = std::string("XMSSMTSHA2256H40D4");
		break;
	case AsymmetricParameters::XMSSMTSHA2256H40D8:
		name = std::string("XMSSMTSHA2256H40D8");
		break;
	case AsymmetricParameters::XMSSMTSHA2256H60D3:
		name = std::string("XMSSMTSHA2256H60D3");
		break;
	case AsymmetricParameters::XMSSMTSHA2256H60D6:
		name = std::string("XMSSMTSHA2256H60D6");
		break;
	case AsymmetricParameters::XMSSMTSHA2256H60D12:
		name = std::string("XMSSMTSHA2256H60D12");
		break;
	case AsymmetricParameters::XMSSMTSHA2512H20D2:
		name = std::string("XMSSMTSHA2512H20D2");
		break;
	case AsymmetricParameters::XMSSMTSHA2512H20D4:
		name = std::string("XMSSMTSHA2512H20D4");
		break;
	case AsymmetricParameters::XMSSMTSHA2512H40D2:
		name = std::string("XMSSMTSHA2512H40D2");
		break;
	case AsymmetricParameters::XMSSMTSHA2512H40D4:
		name = std::string("XMSSMTSHA2512H40D4");
		break;
	case AsymmetricParameters::XMSSMTSHA2512H40D8:
		name = std::string("XMSSMTSHA2512H40D8");
		break;
	case AsymmetricParameters::XMSSMTSHA2512H60D3:
		name = std::string("XMSSMTSHA2512H60D3");
		break;
	case AsymmetricParameters::XMSSMTSHA2512H60D6:
		name = std::string("XMSSMTSHA2512H60D6");
		break;
	case AsymmetricParameters::XMSSMTSHA2512H60D12:
		name = std::string("XMSSMTSHA2512H60D12");
		break;
	case AsymmetricParameters::XMSSMTSHAKE256H20D2:
		name = std::string("XMSSMTSHAKE256H20D2");
		break;
	case AsymmetricParameters::XMSSMTSHAKE256H20D4:
		name = std::string("XMSSMTSHAKE256H20D4");
		break;
	case AsymmetricParameters::XMSSMTSHAKE256H40D2:
		name = std::string("XMSSMTSHAKE256H40D2");
		break;
	case AsymmetricParameters::XMSSMTSHAKE256H40D4:
		name = std::string("XMSSMTSHAKE256H40D4");
		break;
	case AsymmetricParameters::XMSSMTSHAKE256H40D8:
		name = std::string("XMSSMTSHAKE256H40D8");
		break;	
	case AsymmetricParameters::XMSSMTSHAKE256H60D3:
		name = std::string("XMSSMTSHAKE256H60D3");
		break;
	case AsymmetricParameters::XMSSMTSHAKE256H60D6:
		name = std::string("XMSSMTSHAKE256H60D6");
		break;
	case AsymmetricParameters::XMSSMTSHAKE256H60D12:
		name = std::string("XMSSMTSHAKE256H60D12");
		break;
	case AsymmetricParameters::XMSSMTSHAKE512H20D2:
		name = std::string("XMSSMTSHAKE512H20D2");
		break;
	case AsymmetricParameters::XMSSMTSHAKE512H20D4:
		name = std::string("XMSSMTSHAKE512H20D4");
		break;
	case AsymmetricParameters::XMSSMTSHAKE512H40D2:
		name = std::string("XMSSMTSHAKE512H40D2");
		break;
	case AsymmetricParameters::XMSSMTSHAKE512H40D4:
		name = std::string("XMSSMTSHAKE512H40D4");
		break;
	case AsymmetricParameters::XMSSMTSHAKE512H40D8:
		name = std::string("XMSSMTSHAKE512H40D8");
		break;
	case AsymmetricParameters::XMSSMTSHAKE512H60D3:
		name = std::string("XMSSMTSHAKE512H60D3");
		break;
	case AsymmetricParameters::XMSSMTSHAKE512H60D6:
		name = std::string("XMSSMTSHAKE512H60D6");
		break;
	case AsymmetricParameters::XMSSMTSHAKE512H60D12:
		name = std::string("XMSSMTSHAKE512H60D12");
		break;
	default:
		name = std::string("None");
		break;
	}

	return name;
}

AsymmetricParameters AsymmetricTransformConvert::FromName(std::string &Name)
{
	AsymmetricParameters tname;

	if (Name == std::string("DLTMS1P2544"))
	{
		tname = AsymmetricParameters::DLTMS1P2544;
	}
	else if (Name == std::string("DLTMS3P4016"))
	{
		tname = AsymmetricParameters::DLTMS3P4016;
	}
	else if (Name == std::string("DLTMS5P4880"))
	{
		tname = AsymmetricParameters::DLTMS5P4880;
	}
	else if (Name == std::string("ECDHS1P25519K"))
	{
		tname = AsymmetricParameters::ECDHS1P25519K;
	}
	else if (Name == std::string("ECDHS2P25519S"))
	{
		tname = AsymmetricParameters::ECDHS2P25519S;
	}
	else if (Name == std::string("ECDSAS1P25519K"))
	{
		tname = AsymmetricParameters::ECDSAS1P25519K;
	}
	else if (Name == std::string("ECDSAS2P25519S"))
	{
		tname = AsymmetricParameters::ECDSAS2P25519S;
	}
	else if (Name == std::string("KYBERS3P2400"))
	{
		tname = AsymmetricParameters::KYBERS3P2400;
	}
	else if (Name == std::string("KYBERS5P3168"))
	{
		tname = AsymmetricParameters::KYBERS5P3168;
	}
	else if (Name == std::string("KYBERS6P3936"))
	{
		tname = AsymmetricParameters::KYBERS6P3936;
	}
	else if (Name == std::string("MPKCS3N4608T96"))
	{
		tname = AsymmetricParameters::MPKCS3N4608T96;
	}
	else if (Name == std::string("MPKCS3N6960T119"))
	{
		tname = AsymmetricParameters::MPKCS3N6960T119;
	}
	else if (Name == std::string("MPKCS4N6688T128"))
	{
		tname = AsymmetricParameters::MPKCS4N6688T128;
	}
	else if (Name == std::string("MPKCS5N8192T128"))
	{
		tname = AsymmetricParameters::MPKCS5N8192T128;
	}
	else if (Name == std::string("SPXPS1S128SHAKE"))
	{
		tname = AsymmetricParameters::SPXPS1S128SHAKE;
	}
	else if (Name == std::string("SPXPS3S192SHAKE"))
	{
		tname = AsymmetricParameters::SPXPS3S192SHAKE;
	}
	else if (Name == std::string("SPXPS5S256SHAKE"))
	{
		tname = AsymmetricParameters::SPXPS5S256SHAKE;
	}
	else if (Name == std::string("XMSSSHA2256H10"))
	{
		tname = AsymmetricParameters::XMSSSHA2256H16;
	}
	else if (Name == std::string("XMSSSHA2256H16"))
	{
		tname = AsymmetricParameters::XMSSSHA2256H16;
	}
	else if (Name == std::string("XMSSSHA2256H20"))
	{
		tname = AsymmetricParameters::XMSSSHA2256H20;
	}
	else if (Name == std::string("XMSSSHA2512H10"))
	{
		tname = AsymmetricParameters::XMSSSHA2512H10;
	}
	else if (Name == std::string("XMSSSHA2512H16"))
	{
		tname = AsymmetricParameters::XMSSSHA2512H16;
	}
	else if (Name == std::string("XMSSSHA2512H20"))
	{
		tname = AsymmetricParameters::XMSSSHA2512H20;
	}
	else if (Name == std::string("XMSSSHAKE256H10"))
	{
		tname = AsymmetricParameters::XMSSSHAKE256H10;
	}
	else if (Name == std::string("XMSSSHAKE256H16"))
	{
		tname = AsymmetricParameters::XMSSSHAKE256H16;
	}
	else if (Name == std::string("XMSSSHAKE256H20"))
	{
		tname = AsymmetricParameters::XMSSSHAKE256H20;
	}
	else if (Name == std::string("XMSSSHAKE512H10"))
	{
		tname = AsymmetricParameters::XMSSSHAKE512H10;
	}
	else if (Name == std::string("XMSSSHAKE512H16"))
	{
		tname = AsymmetricParameters::XMSSSHAKE512H16;
	}
	else if (Name == std::string("XMSSSHAKE512H20"))
	{
		tname = AsymmetricParameters::XMSSSHAKE512H20;
	}
	else if (Name == std::string("XMSSMTSHA2256H20D2"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2256H20D2;
	}
	else if (Name == std::string("XMSSMTSHA2256H20D4"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2256H20D4;
	}
	else if (Name == std::string("XMSSMTSHA2256H40D2"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2256H40D2;
	}
	else if (Name == std::string("XMSSMTSHA2256H40D4"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2256H40D4;
	}
	else if (Name == std::string("XMSSMTSHA2256H40D8"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2256H40D8;
	}
	else if (Name == std::string("XMSSMTSHA2256H60D3"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2256H60D3;
	}
	else if (Name == std::string("XMSSMTSHA2256H60D6"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2256H60D6;
	}
	else if (Name == std::string("XMSSMTSHA2256H60D12"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2256H60D12;
	}
	else if (Name == std::string("XMSSMTSHA2512H20D2"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2512H20D2;
	}
	else if (Name == std::string("XMSSMTSHA2512H20D4"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2512H20D4;
	}
	else if (Name == std::string("XMSSMTSHA2512H40D2"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2512H40D2;
	}
	else if (Name == std::string("XMSSMTSHA2512H40D4"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2512H40D4;
	}
	else if (Name == std::string("XMSSMTSHA2512H40D8"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2512H40D8;
	}
	else if (Name == std::string("XMSSMTSHA2512H60D3"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2512H60D3;
	}
	else if (Name == std::string("XMSSMTSHA2512H60D6"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2512H60D6;
	}
	else if (Name == std::string("XMSSMTSHA2512H60D12"))
	{
		tname = AsymmetricParameters::XMSSMTSHA2512H60D12;
	}
	else if (Name == std::string("XMSSMTSHAKE256H20D2"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE256H20D2;
	}
	else if (Name == std::string("XMSSMTSHAKE256H20D4"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE256H20D4;
	}
	else if (Name == std::string("XMSSMTSHAKE256H40D2"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE256H40D2;
	}
	else if (Name == std::string("XMSSMTSHAKE256H40D4"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE256H40D4;
	}
	else if (Name == std::string("XMSSMTSHAKE256H40D8"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE256H40D8;
	}
	else if (Name == std::string("XMSSMTSHAKE256H60D3"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE256H60D3;
	}
	else if (Name == std::string("XMSSMTSHAKE256H60D6"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE256H60D6;
	}
	else if (Name == std::string("XMSSMTSHAKE256H60D12"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE256H60D12;
	}
	else if (Name == std::string("XMSSMTSHAKE512H20D2"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE512H20D2;
	}
	else if (Name == std::string("XMSSMTSHAKE512H20D4"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE512H20D4;
	}
	else if (Name == std::string("XMSSMTSHAKE512H40D2"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE512H40D2;
	}
	else if (Name == std::string("XMSSMTSHAKE512H40D4"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE512H40D4;
	}
	else if (Name == std::string("XMSSMTSHAKE512H40D8"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE512H40D8;
	}
	else if (Name == std::string("XMSSMTSHAKE512H60D3"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE512H60D3;
	}
	else if (Name == std::string("XMSSMTSHAKE512H60D6"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE512H60D6;
	}
	else if (Name == std::string("XMSSMTSHAKE512H60D12"))
	{
		tname = AsymmetricParameters::XMSSMTSHAKE512H60D12;
	}
	else
	{
		tname = AsymmetricParameters::None;
	}

	return tname;
}

NAMESPACE_ENUMERATIONEND