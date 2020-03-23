#include "PrngBase.h"
#include "MemoryTools.h"

NAMESPACE_PRNG

using Utility::MemoryTools;

//~~~Constructor~~~//

PrngBase::PrngBase(Prngs Enumeral, std::string Name)
	:
	m_prngEnumeral(Enumeral),
	m_prngName(Name)
{
}

PrngBase::~PrngBase()
{
	m_prngEnumeral = Prngs::None;
	m_prngName = "";
}

//~~~Accessors~~~//

const Prngs PrngBase::Enumeral()
{
	return m_prngEnumeral;
}

const std::string PrngBase::Name()
{
	return m_prngName;
}

//~~~Public Functions~~~//

ushort PrngBase::NextUInt16()
{
	ushort x;
	std::vector<byte> smp(sizeof(ushort));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(ushort));
	MemoryTools::Clear(smp, 0, smp.size());

	return x;
}

uint PrngBase::NextUInt32()
{
	uint x;
	std::vector<byte> smp(sizeof(uint));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint));
	MemoryTools::Clear(smp, 0, smp.size());

	return x;
}

ulong PrngBase::NextUInt64()
{
	ulong x;
	std::vector<byte> smp(sizeof(ulong));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(ulong));
	MemoryTools::Clear(smp, 0, smp.size());

	return x;
}

NAMESPACE_PRNGEND
