#include "CSPRsg.h"

NAMESPACE_SEED

//** Public Methods **//

void CSPRsg::Destroy()
{
#ifdef _WIN32
	if (!::CryptReleaseContext(m_hProvider, 0))
		return;
#endif
}

void CSPRsg::GetBytes(std::vector<byte> &Output)
{
#if defined(_WIN32)
	DWORD dwLength = (DWORD)Output.size();
	BYTE* ptr = (BYTE*)&Output[0];
	if (!::CryptGenRandom(m_hProvider, dwLength, ptr))
	{
		::CryptReleaseContext(m_hProvider, 0);
#	if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoRandomException("CSPRsg:GetBytes", "Call to CryptGenRandom failed; random provider is not available!");
#	endif
	}
#else
	size_t size = Output.size();
	if (size <= 4)
	{
		if (size > 0)
		{
			uint32_t r = arc4random();
			memcpy(&Output[0], &r, size);
		}
	}
	else
	{
		size_t div = size / 4;
		size_t mod = size % 4;

		int i = 0;
		for (int d = 0; d < div; ++d)
		{
			uint32_t r = arc4random();
			byte *rp = (byte*)&r;
			Output[i++] = rp[0];
			Output[i++] = rp[1];
			Output[i++] = rp[2];
			Output[i++] = rp[3];
		}

		if (mod)
		{
			uint32_t r = arc4random();
			memcpy(&Output[i], &r, mod);
		}
	}


#	if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoRandomException("CSPRsg:GetBytes", "Call to arc4random failed; random provider is not available!");
#	endif

#endif
}

std::vector<byte> CSPRsg::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

int CSPRsg::Next()
{
	int ret(0);
	int len = sizeof(ret);
	std::vector<byte> rnd(len);
	GetBytes(rnd);
	memcpy(&ret, &rnd[0], len);

	return ret;
}

void CSPRsg::Reset()
{
#ifdef _WIN32
	if (!::CryptAcquireContextW(&m_hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
#	if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoRandomException("CSPRsg:Reset", "Call to CryptAcquireContextW failed; random provider is not available!");
#	endif
	}
#endif
}

NAMESPACE_SEEDEND