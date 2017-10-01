#ifndef CEX_GHASH_H
#define CEX_GHASH_H

#include "CexDomain.h"

NAMESPACE_MAC

/**
* \internal
*/
/// <summary>
/// Instantiate the GHASH class; this is an *internal class* used by GMAC and GCM mode
/// </summary>
class GHASH
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const std::string CLASS_NAME;

	std::vector<ulong> m_ghashKey;
	bool m_hasCMul;
	std::vector<byte> m_msgBuffer;
	size_t m_msgOffset;

public:

	/// <summary>
	/// 128bit SIMD instructions are available on this system
	/// </summary>
	bool HasSimd128();

	/// <summary>
	/// Instantiate this class; this is an internal class used by GMAC and GCM mode
	/// </summary>
	///
	/// <param name="Key">The ghash key</param>
	explicit GHASH(std::vector<ulong> &Key);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~GHASH();

	/// <summary>
	/// Finalize the GHASH block
	/// </summary>
	///
	/// <param name="Output">The destination array</param>
	/// <param name="AdSize">The size of the AD</param>
	/// <param name="TextSize">The plain text size</param>
	void FinalizeBlock(std::vector<byte> &Output, size_t AdSize, size_t TextSize);

	/// <summary>
	/// Reset the hash function
	/// </summary>
	///
	/// <param name="Erase">Erase the state</param>
	void Reset(bool Erase = false);

	/// <summary>
	/// Process a block of plaintext
	/// </summary>
	///
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The output array</param>
	void ProcessBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output);

	/// <summary>
	/// Process one segment of data
	/// </summary>
	///
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The output array</param>
	/// <param name="Length">The number of bytes to process</param>
	void ProcessSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t Length);

	/// <summary>
	/// Update the hash function
	/// </summary>
	///
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The output array</param>
	/// <param name="Length">The number of bytes to process</param>
	void Update(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t Length);

private:

	void Detect();
	void GcmMultiply(std::vector<byte> &X);
	void Multiply(const std::vector<ulong> &H, std::vector<byte> &X);
	void MultiplyW(const std::vector<ulong> &H, std::vector<byte> &X);
};

NAMESPACE_MACEND
#endif