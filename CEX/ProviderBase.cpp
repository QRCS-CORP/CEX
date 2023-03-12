#include "ProviderBase.h"
#include "MemoryTools.h"

NAMESPACE_PROVIDER

using Tools::MemoryTools;

//~~~Constructor~~~//

ProviderBase::ProviderBase(bool Available, Providers Enumeral, const std::string Name)
	:
	m_isAvailable(Available),
	m_pvdEnumeral(Enumeral),
	m_pvdName(Name)
{
}

ProviderBase::~ProviderBase()
{
	m_isAvailable = false;
	m_pvdEnumeral = Providers::None;
	m_pvdName = std::string("");
}

//~~~Accessors~~~//

const Providers ProviderBase::Enumeral()
{
	return m_pvdEnumeral;
}

const bool ProviderBase::IsAvailable()
{
	return m_isAvailable;
}

const std::string ProviderBase::Name()
{
	return m_pvdName;
}

//~~~Public Functions~~~//

uint16_t ProviderBase::NextUInt16()
{
	uint16_t x;
	SecureVector<uint8_t> smp(sizeof(uint16_t));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint16_t));
	SecureClear(smp);

	return x;
}

uint32_t ProviderBase::NextUInt32()
{
	uint32_t x;
	SecureVector<uint8_t> smp(sizeof(uint32_t));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint32_t));
	SecureClear(smp);

	return x;
}

uint64_t ProviderBase::NextUInt64()
{
	uint64_t x;
	SecureVector<uint8_t> smp(sizeof(uint64_t));

	x = 0;
	Generate(smp);
	MemoryTools::CopyToValue(smp, 0, x, sizeof(uint64_t));
	SecureClear(smp);

	return x;
}

NAMESPACE_PROVIDEREND
