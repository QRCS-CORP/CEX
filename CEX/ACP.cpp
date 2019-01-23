#include "ACP.h"
#include "ArrayTools.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CJP.h"
#include "CSP.h"
#include "RDP.h"
#include "SHAKE.h"
#include "SymmetricKey.h"
#include "SystemTools.h"

NAMESPACE_PROVIDER

using Utility::ArrayTools;
using Enumeration::ErrorCodes;
using Utility::MemoryTools;
using Utility::SystemTools;

const std::string ACP::CLASS_NAME("ACP");
const bool ACP::CPU_HAS_RDRAND = SystemTools::HasRdRand();
const bool ACP::TIMER_HAS_TSC = SystemTools::HasRdtsc();

//~~~Constructor~~~//

ACP::ACP()
	:
#if defined(CEX_FIPS140_ENABLED)
	m_pvdSelfTest(),
#endif
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_POSIX)
	ProviderBase(true, Providers::ACP, CLASS_NAME),
#else
	ProviderBase(false, Providers::ACP, CLASS_NAME),
#endif
	m_kdfGenerator(new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE512))
{
	Reset();
}

ACP::~ACP()
{
	if (m_kdfGenerator != nullptr)
	{
		m_kdfGenerator.reset(nullptr);
	}
}

void ACP::Generate(std::vector<byte> &Output)
{
	if (!IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (!FipsTest())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	GetRandom(Output, 0, Output.size(), m_kdfGenerator);
}

void ACP::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (!IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (!FipsTest())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	GetRandom(Output, Offset, Length, m_kdfGenerator);
}

void ACP::Generate(SecureVector<byte> &Output)
{
	if (!IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (!FipsTest())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	GetRandom(Output, 0, Output.size(), m_kdfGenerator);
}

void ACP::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
{
	if (!IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (!FipsTest())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	GetRandom(Output, Offset, Length, m_kdfGenerator);
}

void ACP::Reset()
{
	std::vector<byte> seed;

	try
	{
		// collect samples from various entropy sources to create the seed
		seed = Collect();

		if (seed.size() == 0)
		{
			throw CryptoRandomException(Name(), std::string("Reset"), std::string("The random generators seed collection has failed!"), ErrorCodes::InvalidState);
		}
	}
	catch (std::exception &ex)
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	CSP cvd;
	// use the system provider to create the customization string
	std::vector<byte> cust(32);
	cvd.Generate(cust);
	// initialize cSHAKE-512
	m_kdfGenerator->Initialize(seed, cust);
}

//~~~Private Functions~~~//

std::vector<byte> ACP::Collect()
{
	const size_t SMPLEN = 32;

	std::vector<byte> state(0);
	std::vector<byte> buffer(SMPLEN);
	ulong ts;

	// add the first timestamp
	ts = SystemTools::TimeStamp(TIMER_HAS_TSC);
	ArrayTools::AppendValue(ts, state);

	// add system state and mix in timer delta
	ArrayTools::AppendVector(MemoryInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(ProcessInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(SystemInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(TimeInfo(), state);

	// filter zeroes
	Filter(state);
	// compress to 512 bits
	state = Compress(state);

	// add rdrand block
	if (CPU_HAS_RDRAND)
	{
		RDP rpv;
		rpv.Generate(buffer);
		ArrayTools::AppendVector(buffer, state);
	}

	// add jitter block
	if (TIMER_HAS_TSC)
	{
		CJP jpv;
		jpv.Generate(buffer);
		ArrayTools::AppendVector(buffer, state);
	}

	return state;
}

std::vector<byte> ACP::Compress(std::vector<byte> &State)
{
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE512);
	std::vector<byte> seed(gen.SecurityLevel() / 8);

	gen.Initialize(State);
	gen.Generate(seed);

	return seed;
}

void ACP::Filter(std::vector<byte> &State)
{
	if (State.size() != 0)
	{
		ArrayTools::Remove(static_cast<byte>(0x00), State);
	}
}

bool ACP::FipsTest()
{
	bool fail;

	fail = false;

#if defined(CEX_FIPS140_ENABLED)

	std::vector<byte> tmp(m_pvdSelfTest.SELFTEST_LENGTH);
	SecureVector<byte> smp(m_pvdSelfTest.SELFTEST_LENGTH);

	GetRandom(tmp, 0, tmp.size(), m_kdfGenerator);
	MemoryTools::Copy(tmp, 0, smp, 0, smp.size());
	MemoryTools::Clear(tmp, 0, tmp.size());

	if (!m_pvdSelfTest.SelfTest(smp))
	{
		fail = true;
	}

#endif

	return (fail == false);
}

void ACP::GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IKdf> &Generator)
{
	Generator->Generate(Output, Offset, Length);
}

void ACP::GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IKdf> &Generator)
{
	std::vector<byte> smp(Length);

	Generator->Generate(smp, 0, Length);
	Insert(smp, 0, Output, Offset, Length);
	Clear(smp);
}

std::vector<byte> ACP::MemoryInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		MEMORYSTATUSEX info = SystemTools::MemoryStatus();

		ArrayTools::AppendObject(&info, state, sizeof(info));
		ArrayTools::AppendValue(SystemTools::MemoryPhysicalTotal(), state);
		ArrayTools::AppendValue(SystemTools::MemoryPhysicalUsed(), state);
		ArrayTools::AppendValue(SystemTools::MemoryVirtualTotal(), state);
		ArrayTools::AppendValue(SystemTools::MemoryVirtualUsed(), state);
	}
	catch (std::exception&)
	{
	}


#elif defined(CEX_OS_POSIX)

	ArrayTools::AppendValue(SystemTools::MemoryPhysicalTotal(), state);
	ArrayTools::AppendValue(SystemTools::MemoryPhysicalUsed(), state);
	ArrayTools::AppendValue(SystemTools::MemoryVirtualTotal(), state);
	ArrayTools::AppendValue(SystemTools::MemoryVirtualUsed(), state);

#endif

	return state;
}

std::vector<byte> ACP::ProcessInfo()
{
	std::vector<byte> state(0);
	size_t i;

#if defined(CEX_OS_WINDOWS)
	try
	{
		std::vector<PROCESSENTRY32W> info = SystemTools::ProcessEntries();

		if (info.size() != 0)
		{
			for (i = 0; i < info.size(); ++i)
			{
				ArrayTools::AppendValue(info[i].pcPriClassBase, state);
				ArrayTools::AppendString(ArrayTools::ToString(info[i].szExeFile), state);
				ArrayTools::AppendValue(info[i].th32ParentProcessID, state);
				ArrayTools::AppendValue(info[i].th32ProcessID, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		std::vector<MODULEENTRY32W> info = SystemTools::ModuleEntries();

		if (info.size() != 0)
		{
			for (i = 0; i < info.size(); ++i)
			{
				ArrayTools::AppendValue(info[i].GlblcntUsage, state);
				ArrayTools::AppendValue(info[i].hModule, state);
				ArrayTools::AppendValue(info[i].modBaseAddr, state);
				ArrayTools::AppendValue(info[i].modBaseSize, state);
				ArrayTools::AppendValue(info[i].ProccntUsage, state);
				ArrayTools::AppendString(ArrayTools::ToString(info[i].szExePath), state);
				ArrayTools::AppendValue(info[i].szModule, state);
				ArrayTools::AppendValue(info[i].th32ModuleID, state);
				ArrayTools::AppendValue(info[i].th32ProcessID, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		std::vector<HEAPENTRY32> info = SystemTools::HeapList();

		if (info.size() != 0)
		{
			ArrayTools::AppendValue(info[0].th32HeapID, state);
			ArrayTools::AppendValue(info[0].th32ProcessID, state);
			ArrayTools::AppendValue(info[0].hHandle, state);

			for (size_t i = 0; i < info.size(); ++i)
			{
				ArrayTools::AppendValue(info[i].dwAddress, state);
				ArrayTools::AppendValue(info[i].dwBlockSize, state);
				ArrayTools::AppendValue(info[i].dwFlags, state);
				ArrayTools::AppendValue(info[i].dwLockCount, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		ArrayTools::AppendVector(SystemTools::ProcessEntries(), state);
	}
	catch (std::exception&)
	{
	}

#endif

	return state;
}

std::vector<byte> ACP::SystemInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)

	POINT pnt = SystemTools::CursorPosition();
	ArrayTools::AppendObject(&pnt, state, sizeof(pnt));

	ArrayTools::AppendString(SystemTools::ComputerName(), state);
	ArrayTools::AppendValue(SystemTools::ProcessId(), state);
	ArrayTools::AppendValue(SystemTools::CurrentThreadId(), state);
	ArrayTools::AppendString(SystemTools::OsVersion(), state);

	try
	{
		SYSTEM_INFO info = SystemTools::SystemInfo();
		ArrayTools::AppendObject(&info, state, sizeof(info));
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		ArrayTools::AppendString(SystemTools::ComputerName(), state);
		ArrayTools::AppendValue(SystemTools::ProcessId(), state);
		ArrayTools::AppendString(SystemTools::DeviceStatistics(), state);
	}
	catch (std::exception&)
	{
	}

#endif

	return state;
}

std::vector<byte> ACP::TimeInfo()
{
	std::vector<byte> state(0);

	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC), state);
	ArrayTools::AppendValue(SystemTools::TimeCurrentNS(), state);
	ArrayTools::AppendValue(SystemTools::TimeSinceBoot(), state);

	return state;
}

NAMESPACE_PROVIDEREND
