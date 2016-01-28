#include "SeedFromName.h"
#include "CSPRsg.h"
#include "ISCRsg.h"
#include "XSPRsg.h"

NAMESPACE_HELPER

using namespace CEX::Seed;

ISeed* SeedFromName::GetInstance(SeedGenerators SeedType)
{
	switch (SeedType)
	{
	case SeedGenerators::CSPRsg:
		return new CSPRsg();
	case SeedGenerators::ISCRsg:
		return new ISCRsg();
	case SeedGenerators::XSPRsg:
		return new XSPRsg();
	default:
		throw CryptoException("SeedFromName:GetInstance", "The specified seed generator type is unrecognized!");
	}
}

NAMESPACE_HELPEREND