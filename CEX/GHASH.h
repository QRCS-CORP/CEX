#ifndef CEX_GHASH_H
#define CEX_GHASH_H

#include "CexDomain.h"

NAMESPACE_MAC

/// 
/// internal
/// 

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

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	GHASH(const GHASH&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	GHASH& operator=(const GHASH&) = delete;

	/// <summary>
	/// Constructor: instantiate this class; this is an internal class used by GMAC and GCM mode
	/// </summary>
	GHASH();

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~GHASH();

	//~~~Accessors~~~//

	/// <summary>
	/// 128bit SIMD instructions are available on this system
	/// </summary>
	bool HasSimd128();

	//~~~Public Functions~~~//

	/// <summary>
	/// Finalize the GHASH block
	/// </summary>
	///
	/// <param name="Output">The destination array</param>
	/// <param name="AdSize">The size of the AD</param>
	/// <param name="TextSize">The plain text size</param>
	void FinalizeBlock(std::vector<byte> &Output, size_t AdSize, size_t TextSize);

	/// <summary>
	/// Initialize the hash key
	/// </summary>
	///
	/// <param name="Key">The ghash key</param>
	void Initialize(const std::vector<ulong> &Key);

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
	/// Reset the hash function
	/// </summary>
	///
	/// <param name="Erase">Erase the state</param>
	void Reset(bool Erase = false);

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
