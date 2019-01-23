#include "PrngBase.h"
#include "MemoryTools.h"

NAMESPACE_PRNG

using Utility::MemoryTools;

//~~~PrngBase~~~//

PrngBase::PrngBase(Prngs Enumeral)
	:
	m_prngEnumeral(Enumeral)
{
}

PrngBase::~PrngBase()
{
	m_prngEnumeral = Prngs::None;
}

//~~~Accessors~~~//

const Prngs PrngBase::Enumeral()
{
	return m_prngEnumeral;
}

//~~~Public Functions~~~//

ushort PrngBase::NextUInt16()
{
	ushort x;
	std::vector<byte> smp(sizeof(ushort));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(ushort));
	Clear(smp);

	return x;
}

uint PrngBase::NextUInt32()
{
	uint x;
	std::vector<byte> smp(sizeof(uint));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint));
	Clear(smp);

	return x;
}

ulong PrngBase::NextUInt64()
{
	ulong x;
	std::vector<byte> smp(sizeof(ulong));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(ulong));
	Clear(smp);

	return x;
}

NAMESPACE_PRNGEND
