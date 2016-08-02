#ifndef _CEXENGINE_XSPPRSG_H
#define _CEXENGINE_XSPPRSG_H

#include "ISeed.h"

NAMESPACE_SEED

/// <summary>
/// XSPRsg: Generates seed material using an XorShift+ generator.
/// <para>This generator is not generally considered a cryptographic quality generator. 
/// This generator is suitable as a quality high-speed number generator, but not to be used directly for tasks that require secrecy, ex. key generation.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// XSPRsg gen(Seed);
/// gen.GetSeed(Output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Further scramblings of Marsaglia’s <a href="http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf">Xorshift Generators</a>.</description></item>
/// <item><description><a href="http://xorshift.di.unimi.it/">Xorshift+ generators</a> and the PRNG shootout.</description></item>
/// </list>
/// </remarks>
class XSPRsg : public ISeed
{
private:
	static constexpr int SIZE32 = 4;
	static constexpr int SIZE64 = 8;
	static constexpr int MAXSEED = 16;
	static constexpr ulong Z1 = 0x9E3779B97F4A7C15;
	static constexpr ulong Z2 = 0xBF58476D1CE4E5B9;
	static constexpr ulong Z3 = 0x94D049BB133111EB;
	static constexpr ulong Z4 = 1181783497276652981;

	bool m_isDestroyed;
	bool m_isShift1024;
	size_t m_stateOffset;
	std::vector<ulong> m_stateSeed;
	std::vector<ulong> m_wrkBuffer;
	std::vector<ulong> JMP128;
	std::vector<ulong> JMP1024;

public:
	// *** Properties *** //

	/// <summary>
	/// Get: The seed generators type name
	/// </summary>
	virtual const CEX::Enumeration::SeedGenerators Enumeral() { return CEX::Enumeration::SeedGenerators::XSPRsg; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "XSPRsg"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize this class using the default random provider to generate 16 ulongs and invoke the 1024 bit function
	/// </summary>
	XSPRsg()
		:
		m_isDestroyed(false),
		m_isShift1024(false),
		m_stateOffset(0),
		m_stateSeed(MAXSEED),
		m_wrkBuffer(MAXSEED)
	{
		size_t len = MAXSEED * sizeof(ulong);
		GetSeed(len);
		m_isShift1024 = true;

		JMP1024 = { 
			0x84242f96eca9c41dULL, 0xa3c65b8776f96855ULL, 0x5b34a39f070b5837ULL, 0x4489affce4f31a1eULL, 
			0x2ffeeb0a48316f40ULL, 0xdc2d9891fe68c022ULL, 0x3659132bb12fea70ULL, 0xaac17d8efa43cab8ULL, 
			0xc4cb815590989b13ULL, 0x5ee975283d71c93bULL, 0x691548c86c1bd540ULL, 0x7910c41d10a1e6a5ULL, 
			0x0b5fc64563b3e2a8ULL, 0x047f7684e9fc949dULL, 0xb99181f2d8f685caULL, 0x284600e3f30e38c3ULL
		};

		Reset();
	}

	/// <summary>
	/// Initialize this class with a random seed array.
	/// <para>Initializing with 2 ulongs invokes the 128 bit function, initializing with 16 ulongs
	/// invokes the 1024 bit function.</para>
	/// </summary>
	///
	/// <param name="Seed">The initial state values; can be either 2, or 16, 64bit values</param>
	///
	/// <exception cref="CEX::Exception::CryptoRandomException">Thrown if an invalid seed size is used</exception>
	explicit XSPRsg(const std::vector<ulong> &Seed)
		:
		m_isDestroyed(false),
		m_isShift1024(false),
		m_stateOffset(0),
		m_stateSeed(Seed.size()),
		m_wrkBuffer(Seed.size())
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Seed.size() != 2 && Seed.size() != 16)
			throw CryptoRandomException("XSPRsg:CTor", "The seed array length must be either 2 or 16 long values!");

		for (size_t i = 0; i < Seed.size(); ++i)
		{
			if (Seed[i] == 0)
				throw CryptoRandomException("XSPRsg:CTor", "Seed values can not be zero!");
		}
#endif
		size_t len = Seed.size() * sizeof(ulong);
		memcpy(&m_stateSeed[0], &Seed[0], len);
		m_isShift1024 = (Seed.size() == 16);

		if (!m_isShift1024)
			JMP128 = { 0x8a5cd789635d2dffULL, 0x121fd2155c472f96ULL };
		else
			JMP1024 = { 
				0x84242f96eca9c41dULL, 0xa3c65b8776f96855ULL, 0x5b34a39f070b5837ULL, 0x4489affce4f31a1eULL,
				0x2ffeeb0a48316f40ULL, 0xdc2d9891fe68c022ULL, 0x3659132bb12fea70ULL, 0xaac17d8efa43cab8ULL,
				0xc4cb815590989b13ULL, 0x5ee975283d71c93bULL, 0x691548c86c1bd540ULL, 0x7910c41d10a1e6a5ULL,
				0x0b5fc64563b3e2a8ULL, 0x047f7684e9fc949dULL, 0xb99181f2d8f685caULL, 0x284600e3f30e38c3ULL
			};

		Reset();
	}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~XSPRsg()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Fill the buffer with random bytes
	/// </summary>
	///
	/// <param name="Output">The array to fill</param>
	virtual void GetBytes(std::vector<byte> &Output);

	/// <summary>
	/// Get a pseudo random seed byte array
	/// </summary>
	/// 
	/// <param name="Size">The size of the expected seed returned</param>
	/// 
	/// <returns>A pseudo random seed</returns>
	virtual std::vector<byte> GetBytes(size_t Size);

	/// <summary>
	/// Increment the state by 64 blocks; used with the 128 and 1024 implementations
	/// </summary>
	void Jump();

	/// <summary>
	/// Returns the next pseudo random 32bit integer
	/// </summary>
	/// 
	/// <returns>A pseudo random 32bit integer</returns>
	virtual int Next();

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Implementation of java's Splittable function
	/// </summary>
	/// 
	/// <param name="X">Input integer</param>
	/// 
	/// <returns>A processed long integer</returns>
	ulong Split(ulong X);

private:
	void Jump128();
	void Jump1024();
	void Generate(std::vector<byte> &Output, size_t Size);
	void GetSeed(size_t Size);
	ulong Shift128();
	ulong Shift1024();
};

NAMESPACE_SEEDEND
#endif
