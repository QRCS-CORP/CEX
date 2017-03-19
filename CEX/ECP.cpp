#include "ECP.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "CpuDetect.h"
#include "CSP.h"
#include "Keccak512.h"
#include "SymmetricKey.h"
#include "SysUtils.h"

NAMESPACE_PROVIDER

using Utility::ArrayUtils;
using Utility::SysUtils;

//~~~Constructor~~~//

ECP::ECP()
	:
	m_isAvailable(false)
{
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_ANDROID) || defined(CEX_OS_POSIX)
	m_isAvailable = true;
#endif

	Reset();
}

ECP::~ECP()
{
	Destroy();
}

//~~~Public Functions~~~//

void ECP::Destroy()
{
	if (m_cipherMode != 0)
		delete m_cipherMode;
}

void ECP::GetBytes(std::vector<byte> &Output)
{
	GetBytes(Output, 0, Output.size());
}

void ECP::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (!m_isAvailable)
		throw CryptoRandomException("ECP:Engine", "Random provider is not available!");
	if (Offset + Length > Output.size())
		throw CryptoRandomException("ECP:GetBytes", "The array is too small to fulfill this request!");

	std::vector<byte> data(Length);
	m_cipherMode->Transform(data, 0, Output, Offset);
}

std::vector<byte> ECP::GetBytes(size_t Length)
{
	std::vector<byte> data(Length);
	GetBytes(data);

	return data;
}

uint ECP::Next()
{
	uint rndNum;
	std::vector<byte> rnd(sizeof(uint));
	GetBytes(rnd);
	memcpy(&rndNum, &rnd[0], sizeof(uint));

	return rndNum;
}

void ECP::Reset()
{
	std::vector<byte> key;

	try
	{
		// collect entropy, filter, and compress
		key = Collect();
	}
	catch (std::exception &ex)
	{
		throw CryptoRandomException("ECP:Reset", "Entropy collection has failed!", std::string(ex.what()));
	}

	// initialize the cipher
	m_cipherMode = Helper::CipherModeFromName::GetInstance(Enumeration::CipherModes::CTR, Enumeration::BlockCiphers::AHX);

	// get the iv and hkdf info from system provider
	std::vector<byte> info(m_cipherMode->LegalKeySizes()[0].InfoSize());
	std::vector<byte> iv(16);
	CSP pvd;
	pvd.GetBytes(info);
	pvd.GetBytes(iv);
	Key::Symmetric::SymmetricKey kp(key, iv, info);
	m_cipherMode->Initialize(true, kp);
}

//~~~Private Functions~~~//

std::vector<byte> ECP::Collect()
{
	const size_t KBLK = 136;

	std::vector<byte> sysState(0);
	std::vector<byte> rndBuffer(KBLK);
	ulong ts = SysUtils::TimeStamp();

	CSP pvd;
	pvd.GetBytes(rndBuffer);
	// first block is system provider
	ArrayUtils::Append(rndBuffer, sysState);
	// get the first timestamp
	ArrayUtils::Append(ts, sysState);
	// collect the entropy
	ArrayUtils::Append(DriveInfo(), sysState);
	ArrayUtils::Append(SysUtils::TimeStamp() - ts, sysState);
	ArrayUtils::Append(MemoryInfo(), sysState);
	ArrayUtils::Append(SysUtils::TimeStamp() - ts, sysState);
	ArrayUtils::Append(NetworkInfo(), sysState);
	ArrayUtils::Append(SysUtils::TimeStamp() - ts, sysState);
	ArrayUtils::Append(ProcessInfo(), sysState);
	ArrayUtils::Append(SysUtils::TimeStamp() - ts, sysState);
	ArrayUtils::Append(ProcessorInfo(), sysState);
	ArrayUtils::Append(SysUtils::TimeStamp() - ts, sysState);
	ArrayUtils::Append(SystemInfo(), sysState);
	ArrayUtils::Append(SysUtils::TimeStamp() - ts, sysState);
	ArrayUtils::Append(TimeInfo(), sysState);
	ArrayUtils::Append(SysUtils::TimeStamp() - ts, sysState);
	ArrayUtils::Append(UserInfo(), sysState);
	ArrayUtils::Append(SysUtils::TimeStamp() - ts, sysState);

	// last block size
	size_t padLen = ((sysState.size() % KBLK) == 0) ? KBLK : KBLK - (sysState.size() % KBLK);
	if (padLen < KBLK / 2)
		padLen += KBLK;

	// forward padding
	rndBuffer.resize(padLen);
	pvd.GetBytes(rndBuffer);
	ArrayUtils::Append(rndBuffer, sysState);

	// filter zeroes and shuffle
	Filter(sysState);

	return Compress(sysState);
}

std::vector<byte> ECP::Compress(std::vector<byte> &State)
{
	Digest::Keccak512 dgt;
	std::vector<byte> outKey(dgt.DigestSize());
	dgt.Compute(State, outKey);

	return outKey;
}

void ECP::Filter(std::vector<byte> &State)
{
	// filter zero bytes and shuffle
	if (State.size() == 0)
		return;

	ArrayUtils::Remove((byte)0, State);
}

std::vector<byte> ECP::DriveInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)
	std::vector<std::string> drives = SysUtils::LogicalDrives();

	for (size_t i = 0; i < drives.size(); ++i)
		ArrayUtils::Append(SysUtils::DriveSpace(drives[i]), sysState);

#elif defined(CEX_OS_POSIX)
	// TODO
#endif

	return sysState;
}

std::vector<byte> ECP::MemoryInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		MEMORYSTATUSEX info = SysUtils::MemoryStatus();

		ArrayUtils::Append(info.dwMemoryLoad, sysState);
		ArrayUtils::Append(info.ullAvailExtendedVirtual, sysState);
		ArrayUtils::Append(info.ullAvailPageFile, sysState);
		ArrayUtils::Append(info.ullAvailPhys, sysState);
		ArrayUtils::Append(info.ullAvailVirtual, sysState);
		ArrayUtils::Append(info.ullTotalPageFile, sysState);
		ArrayUtils::Append(info.ullTotalPhys, sysState);
		ArrayUtils::Append(info.ullTotalVirtual, sysState);
		ArrayUtils::Append(SysUtils::MemoryPhysicalTotal(), sysState);
		ArrayUtils::Append(SysUtils::MemoryPhysicalUsed(), sysState);
		ArrayUtils::Append(SysUtils::MemoryVirtualTotal(), sysState);
		ArrayUtils::Append(SysUtils::MemoryVirtualUsed(), sysState);
	}
	catch (...)
	{
	}


#elif defined(CEX_OS_POSIX)

	ArrayUtils::Append(SysUtils::MemoryPhysicalTotal(), sysState);
	ArrayUtils::Append(SysUtils::MemoryPhysicalUsed(), sysState);
	ArrayUtils::Append(SysUtils::MemoryVirtualTotal(), sysState);
	ArrayUtils::Append(SysUtils::MemoryVirtualUsed(), sysState);

#endif

	return sysState;
}

std::vector<byte> ECP::NetworkInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)

	try
	{
		std::vector<PIP_ADAPTER_INFO> info = SysUtils::AdaptersInfo();

		for (size_t i = 0; i < info.size(); ++i)
		{
			ArrayUtils::Append(ArrayUtils::ToString(info[i]->AdapterName), sysState);
			ArrayUtils::Append(ArrayUtils::ToByteArray(info[i]->Address, 8), sysState);
			ArrayUtils::Append(info[i]->ComboIndex, sysState);
			ArrayUtils::Append(ArrayUtils::ToString(info[i]->Description), sysState);
			ArrayUtils::Append(info[i]->DhcpServer.IpAddress.String, sysState);
			ArrayUtils::Append(info[i]->IpAddressList.IpAddress.String, sysState);
			ArrayUtils::Append(info[i]->LeaseExpires, sysState);
		}
	}
	catch (...)
	{
	}

	try
	{
		MIB_TCPSTATS info = SysUtils::TcpStatistics();

		ArrayUtils::Append(info.dwActiveOpens, sysState);
		ArrayUtils::Append(info.dwAttemptFails, sysState);
		ArrayUtils::Append(info.dwCurrEstab, sysState);
		ArrayUtils::Append(info.dwEstabResets, sysState);
		ArrayUtils::Append(info.dwInErrs, sysState);
		ArrayUtils::Append(info.dwInSegs, sysState);
		ArrayUtils::Append(info.dwMaxConn, sysState);
		ArrayUtils::Append(info.dwNumConns, sysState);
		ArrayUtils::Append(info.dwOutRsts, sysState);
		ArrayUtils::Append(info.dwOutSegs, sysState);
		ArrayUtils::Append(info.dwPassiveOpens, sysState);
		ArrayUtils::Append(info.dwRetransSegs, sysState);
		ArrayUtils::Append(info.dwRtoAlgorithm, sysState);
		ArrayUtils::Append(info.dwRtoMax, sysState);
		ArrayUtils::Append(info.dwRtoMin, sysState);
		ArrayUtils::Append(info.RtoAlgorithm, sysState);
	}
	catch (...)
	{
	}

#elif defined(CEX_OS_POSIX)
	// TODO
#endif

	return sysState;
}

std::vector<byte> ECP::ProcessInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		std::vector<PROCESSENTRY32W> info = SysUtils::ProcessEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			ArrayUtils::Append(info[i].pcPriClassBase, sysState);
			ArrayUtils::Append(info[i].szExeFile, sysState);
			ArrayUtils::Append(info[i].th32ParentProcessID, sysState);
			ArrayUtils::Append(info[i].th32ProcessID, sysState);
		}
	}
	catch (...)
	{
	}

	try
	{
		std::vector<MODULEENTRY32W> info = SysUtils::ModuleEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			ArrayUtils::Append(info[i].GlblcntUsage, sysState);
			ArrayUtils::Append(info[i].hModule, sysState);
			ArrayUtils::Append(info[i].modBaseAddr, sysState);
			ArrayUtils::Append(info[i].modBaseSize, sysState);
			ArrayUtils::Append(info[i].ProccntUsage, sysState);
			ArrayUtils::Append(info[i].szExePath, sysState);
			ArrayUtils::Append(info[i].szModule, sysState);
			ArrayUtils::Append(info[i].th32ModuleID, sysState);
			ArrayUtils::Append(info[i].th32ProcessID, sysState);
		}
	}
	catch (...)
	{
	}

	try
	{
		std::vector<HEAPENTRY32> info = SysUtils::HeapList();

		if (info.size() != 0)
		{
			ArrayUtils::Append(info[0].th32HeapID, sysState);
			ArrayUtils::Append(info[0].th32ProcessID, sysState);
			ArrayUtils::Append(info[0].hHandle, sysState);

			for (size_t i = 0; i < info.size(); ++i)
			{
				ArrayUtils::Append(info[i].dwAddress, sysState);
				ArrayUtils::Append(info[i].dwBlockSize, sysState);
				ArrayUtils::Append(info[i].dwFlags, sysState);
				ArrayUtils::Append(info[i].dwLockCount, sysState);
			}
		}
	}
	catch (...)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		ArrayUtils::Append(SysUtils::ProcessEntries(), sysState);
	}
	catch (...)
	{
	}

#endif

	return sysState;
}

std::vector<byte> ECP::ProcessorInfo()
{
	std::vector<byte> sysState(0);
	Common::CpuDetect detect;

	ArrayUtils::Append(detect.BusSpeed(), sysState);
	ArrayUtils::Append(detect.FrequencyBase(), sysState);
	ArrayUtils::Append(detect.FrequencyMax(), sysState);
	ArrayUtils::Append(detect.FrequencyBase(), sysState);
	ArrayUtils::Append(detect.SerialNumber(), sysState);

	return sysState;
}

std::vector<byte> ECP::SystemInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)

	POINT pnt = SysUtils::CursorPosition();

	ArrayUtils::Append(pnt.x, sysState);
	ArrayUtils::Append(pnt.y, sysState);
	ArrayUtils::Append(SysUtils::ComputerName(), sysState);
	ArrayUtils::Append(SysUtils::ProcessId(), sysState);
	ArrayUtils::Append(SysUtils::CurrentThreadId(), sysState);
	ArrayUtils::Append(SysUtils::OsVersion(), sysState);

	std::vector<std::string> clsids = SysUtils::SystemIds();
	for (size_t i = 0; i < clsids.size(); ++i)
		ArrayUtils::Append(clsids[i], sysState);

	try
	{
		SYSTEM_INFO info = SysUtils::SystemInfo();

		ArrayUtils::Append(info.dwActiveProcessorMask, sysState);
		ArrayUtils::Append(info.dwAllocationGranularity, sysState);
		ArrayUtils::Append(info.dwNumberOfProcessors, sysState);
		ArrayUtils::Append(info.dwPageSize, sysState);
		ArrayUtils::Append(info.dwProcessorType, sysState);
		ArrayUtils::Append(info.lpMaximumApplicationAddress, sysState);
		ArrayUtils::Append(info.lpMinimumApplicationAddress, sysState);
		ArrayUtils::Append(info.wProcessorLevel, sysState);
		ArrayUtils::Append(info.wProcessorRevision, sysState);
	}
	catch (...)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		ArrayUtils::Append(SysUtils::ComputerName(), sysState);
		ArrayUtils::Append(SysUtils::ProcessId(), sysState);
		ArrayUtils::Append(SysUtils::SystemInfo(), sysState);
	}
	catch (...)
	{
	}

#endif

	return sysState;
}

std::vector<byte> ECP::TimeInfo()
{
	std::vector<byte> sysState(0);

	ArrayUtils::Append(SysUtils::TimeStamp(), sysState);
	ArrayUtils::Append(SysUtils::TimeCurrentNS(), sysState);
	ArrayUtils::Append(SysUtils::TimeSinceBoot(), sysState);

	return sysState;
}

std::vector<byte> ECP::UserInfo()
{
	std::vector<byte> sysState(0);

	ArrayUtils::Append(SysUtils::UserName(), sysState);
	ArrayUtils::Append(SysUtils::UserId(), sysState);

	return sysState;
}

NAMESPACE_PROVIDEREND