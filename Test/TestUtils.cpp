#include "TestUtils.h"
#include "TestException.h"
#include "../CEX/CexDomain.h"
#include "../CEX/CSP.h"
#if defined(_WIN32)
#	include <Windows.h>
#else
#	include <sys/types.h>
#	include <sys/time.h>
#endif
#include <fstream>
#include <iostream>
#include <math.h>

namespace Test
{
	using CEX::Provider::CSP;

#define	ex(x) (((x) < -BIGX) ? 0.0 : exp(x))

	const double TestUtils::Z_MAX = 6.0;
	const double TestUtils::LOG_SQRT_PI = 0.5723649429247000870717135;
	const double TestUtils::I_SQRT_PI = 0.5641895835477562869480795;
	const double TestUtils::BIGX = 20.0;

	double TestUtils::ChiSquare(std::vector<byte> &Input)
	{
		std::vector<long> count(256, 0);
		double a;
		double cexp;
		double chisq(0.0);
		long totalc;
		size_t i;

		totalc = static_cast<long>(Input.size());

		for (i = 0; i < Input.size(); ++i)
		{
			count[Input[i]]++;
		}

		// Expected count per bin
		cexp = static_cast<double>(totalc) / 256.0;

		for (i = 0; i < 256; i++)
		{
			a = static_cast<double>(count[i]) - cexp;
			chisq += (a * a) / cexp;
		}

		return PoChiSq(chisq, 255);
	}

	void TestUtils::CopyVector(const std::vector<int> &SrcArray, size_t SrcIndex, std::vector<int> &DstArray, size_t DstIndex, size_t Length)
	{
		std::memcpy(&DstArray[DstIndex], &SrcArray[SrcIndex], Length * sizeof(SrcArray[SrcIndex]));
	}

	bool TestUtils::IsEqual(std::vector<byte> &A, std::vector<byte> &B)
	{
		size_t i = A.size();
		bool res(true);

		if (i != B.size())
		{
			res = false;
		}

		while (i != 0)
		{
			--i;

			if (A[i] != B[i])
			{
				res = false;
			}
		}

		return res;
	}

	uint64_t TestUtils::GetTimeMs64()
	{
#if defined(_WIN32)
		// Windows
		int64_t ctr1(0);
		int64_t freq(0);

		if (QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&ctr1)) != 0)
		{
			QueryPerformanceFrequency(reinterpret_cast<LARGE_INTEGER*>(&freq));

			if (freq == 0)
			{
				throw;
			}
			// return microseconds to milliseconds
			return ((ctr1 * 1000) / freq);
		}
		else
		{
			FILETIME ft;
			LARGE_INTEGER li;

			// Get the amount of 100 nano seconds intervals elapsed since January 1, 1601 (UTC) and copy it to a LARGE_INTEGER structure
			GetSystemTimeAsFileTime(&ft);
			li.LowPart = ft.dwLowDateTime;
			li.HighPart = ft.dwHighDateTime;

			uint64_t ret = li.QuadPart;
			ret -= 116444736000000000LL; // Convert from file time to UNIX epoch time.
			ret /= 10000; // From 100 nano seconds (10^-7) to 1 millisecond (10^-3) intervals

			return ret;
		}
#else
		// Linux
		struct timeval tv;

		gettimeofday(&tv, NULL);
		uint64_t ret = tv.tv_usec;
		// Convert from micro seconds (10^-6) to milliseconds (10^-3)
		ret /= 1000;
		// Adds the seconds (10^0) after converting them to milliseconds (10^-3)
		ret += (tv.tv_sec * 1000);

		return ret;
#endif
	}

	void TestUtils::GetRandom(std::vector<byte> &Data)
	{
		CSP rng;
		rng.Generate(Data);
	}

	SymmetricKey* TestUtils::GetRandomKey(size_t KeySize, size_t IvSize)
	{
		CSP rng;
		SymmetricKey* kp;
		std::vector<byte> key(KeySize, 0);

		rng.Generate(key);

		if (IvSize > 0)
		{
			std::vector<byte> iv(IvSize, 0);
			rng.Generate(iv);
			kp = new SymmetricKey(key, iv);
		}
		else
		{
			kp =  new SymmetricKey(key);
		}

		return kp;
	}

	std::string TestUtils::GetRandomString(size_t Length)
	{
		std::string res;

		res = TestUtils::RandomReadableString(Length);

		return res;
	}

	double TestUtils::MeanValue(std::vector<byte> &Input)
	{
		double ret(0);
		size_t i;

		for (i = 0; i < Input.size(); ++i)
		{
			ret += static_cast<double>(Input[i]);
		}

		return ret / static_cast<double>(Input.size());
	}

	bool TestUtils::OrderedRuns(const std::vector<byte> &Input, size_t Threshold)
	{
		size_t c(0);
		size_t i;
		byte val;
		bool state(false);

		val = Input[0];

		// indicates zeroed output or bad run
		for (i = 1; i < Input.size(); ++i)
		{
			if (Input[i] == val)
			{
				++c;

				if (c >= Threshold)
				{
					state = true;
					break;
				}
			}
			else
			{
				val = Input[i];
				c = 0;
			}
		}

		return state;
	}

	double TestUtils::Poz(const double Z)
	{
		// borrowed from the ENT project: https://www.fourmilab.ch/random/
		// returns cumulative probability from -oo to z 
		double w;
		double x;
		double y;

		if (Z == 0.0)
		{
			x = 0.0;
		}
		else
		{
			y = 0.5 * fabs(Z);
			if (y >= (Z_MAX * 0.5))
			{
				x = 1.0;
			}
			else if (y < 1.0)
			{
				w = y * y;
				x = ((((((((0.000124818987 * w
					- 0.001075204047) * w + 0.005198775019) * w
					- 0.019198292004) * w + 0.059054035642) * w
					- 0.151968751364) * w + 0.319152932694) * w
					- 0.531923007300) * w + 0.797884560593) * y * 2.0;
			}
			else
			{
				y -= 2.0;
				x = (((((((((((((-0.000045255659 * y
					+ 0.000152529290) * y - 0.000019538132) * y
					- 0.000676904986) * y + 0.001390604284) * y
					- 0.000794620820) * y - 0.002034254874) * y
					+ 0.006549791214) * y - 0.010557625006) * y
					+ 0.011630447319) * y - 0.009279453341) * y
					+ 0.005353579108) * y - 0.002141268741) * y
					+ 0.000535310849) * y + 0.999936657524;
			}
		}

		return (Z > 0.0 ? ((x + 1.0) * 0.5) : ((1.0 - x) * 0.5));
	}

	double TestUtils::PoChiSq(const double Ax, const int Df)
	{
		// obtained chi-square value
		// degrees of freedom
		double x;
		double a; 
		double s;
		double e;
		double c;
		double z;
		double y(0);
		double res;
		// true if df is an even number
		int even;

		x = Ax;

		if (x <= 0.0 || Df < 1)
		{
			res = 1.0;
		}

		a = 0.5 * x;
		even = (2 * (Df / 2)) == Df;

		if (Df > 1)
		{
			y = ex(-a);
		}

		s = (even ? y : (2.0 * Poz(-sqrt(x))));

		if (Df > 2)
		{
			x = 0.5 * (static_cast<double>(Df) - 1.0);
			z = (even ? 1.0 : 0.5);

			if (a > BIGX)
			{
				e = (even ? 0.0 : LOG_SQRT_PI);
				c = log(a);

				while (z <= x)
				{
					e = log(z) + e;
					s += ex(c * z - a - e);
					z += 1.0;
				}

				res =s;
			}
			else
			{
				e = (even ? 1.0 : (I_SQRT_PI / sqrt(a)));
				c = 0.0;

				while (z <= x)
				{
					e = e * (a / z);
					c = c + e;
					z += 1.0;
				}

				res = (c * y + s);
			}
		}
		else
		{
			res = s;
		}

		return res;
	}

	void TestUtils::Print(const std::string &Data)
	{
		std::cout << Data << std::endl;
	}

	void TestUtils::PrintHex(byte* Data, size_t Size)
	{
		std::cout << ToHex(Data, Size);
	}

	std::string TestUtils::RandomReadableString(size_t Length)
	{
		std::vector<byte> fill(1);
		CEX::Prng::SecureRandom rnd;
		std::string rtxt("");
		size_t ctr = 0;

		while (ctr < Length)
		{
			rnd.Generate(fill);

			if (fill[0] > 31 && fill[0] < 123 && (fill[0] != 39 && fill[0] != 40 && fill[0] != 41))
			{

				rtxt += static_cast<unsigned char>(fill[0]);
				++ctr;
			}
		}

		return rtxt;
	}

	bool TestUtils::Read(const std::string &FilePath, std::string &Contents) 
	{
		bool status(false);
		std::ifstream ifs(FilePath, std::ios::binary | std::ios::ate);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}
		else
		{
			ifs.seekg(0, std::ios::end);
			const int BUFLEN = static_cast<int>(ifs.tellg());
			ifs.seekg(0, std::ios::beg);

			if (BUFLEN > 0)
			{
				status = true;
				std::vector<char> bufv(BUFLEN, 0);
				char *buf = &bufv[0];
				ifs.read(buf, BUFLEN);
				Contents.assign(buf, BUFLEN);
			}
			else
			{
				throw TestException(std::string("Read"), FilePath, std::string("The file is empty!"));
			}
		}

		return status;
	}

	std::ifstream TestUtils::OpenFile(std::string &FilePath)
	{
		std::ifstream ifs(FilePath, std::ios::binary | std::ios::ate);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("OpenFile"), FilePath, std::string("Could not open the file!"));
		}
		else
		{
			return ifs;
		}
	}

	std::vector<byte> TestUtils::Reduce(std::vector<byte> Seed)
	{
		const size_t SEEDLEN = Seed.size() / 2;
		std::vector<byte> data(SEEDLEN);

		for (size_t i = 0; i < SEEDLEN; i++)
		{
			data[i] = static_cast<byte>(Seed[i] ^ Seed[SEEDLEN + i]);
		}

		return data;
	}

	void TestUtils::Reverse(std::vector<byte> &Data)
	{
		std::reverse(Data.begin(), Data.end());
	}

	bool TestUtils::SuccesiveZeros(const std::vector<byte> &Input, size_t Threshold)
	{
		size_t c(0);
		size_t i;
		bool state(false);

		for (i = 0; i < Input.size(); ++i)
		{
			if (Input[i] == 0x00)
			{
				++c;
				if (c >= Threshold)
				{
					state = true;
					break;
				}
			}
			else
			{
				c = 0;
			}
		}

		return state;
	}

	void TestUtils::WaitForInput()
	{
		std::string resp = "";

		try
		{
			std::getline(std::cin, resp);
		}
		catch (std::exception&)
		{
		}
	}
}
