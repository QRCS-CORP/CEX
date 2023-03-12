#include "PrngBase.h"
#include "MemoryTools.h"

NAMESPACE_PRNG

using Tools::MemoryTools;

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

uint16_t PrngBase::NextUInt16()
{
	uint16_t x;
	std::vector<uint8_t> smp(sizeof(uint16_t));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint16_t));
	MemoryTools::Clear(smp, 0, smp.size());

	return x;
}

uint32_t PrngBase::NextUInt32()
{
	uint32_t x;
	std::vector<uint8_t> smp(sizeof(uint32_t));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint32_t));
	MemoryTools::Clear(smp, 0, smp.size());

	return x;
}

uint64_t PrngBase::NextUInt64()
{
	uint64_t x;
	std::vector<uint8_t> smp(sizeof(uint64_t));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint64_t));
	MemoryTools::Clear(smp, 0, smp.size());

	return x;
}

NAMESPACE_PRNGEND
