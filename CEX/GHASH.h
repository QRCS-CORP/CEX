#ifndef CEX_GHASH_H
#define CEX_GHASH_H

#include "CexDomain.h"
#include "CMUL.h"

NAMESPACE_DIGEST

using Numeric::CMUL;

/// 
/// TODO: make this into a proper digest.. optimize
/// 

/// <summary>
/// Instantiate the GHASH class; this is an *internal class* used by GMAC and GCM mode
/// </summary>
class GHASH
{
private:

	static const std::string CLASS_NAME;
	static const bool HAS_CMUL;

	class GhashState;
	std::unique_ptr<GhashState> m_ghashState;

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

	//~~~Public Functions~~~//

	/// <summary>
	/// Clear the message buffer but retain the key state
	/// </summary>
	void Clear();

	/// <summary>
	/// Finalize the GHASH block
	/// </summary>
	///
	/// <param name="Output">The destination array</param>
	/// <param name="Counter">The size of the AD</param>
	/// <param name="Length">The plain text size</param>
	void Finalize(std::vector<byte> &Output, size_t Counter, size_t Length);

	/// <summary>
	/// Initialize the hash key
	/// </summary>
	///
	/// <param name="Key">The ghash key</param>
	void Initialize(const std::vector<ulong> &Key);

	/// <summary>
	/// Process one segment of data
	/// </summary>
	///
	/// <param name="Input">The source array</param>
	/// <param name="Output">The output array</param>
	/// <param name="Length">The number of input bytes to process</param>
	void Multiply(const std::vector<byte> &Input, std::vector<byte> &Output, size_t Length);

	/// <summary>
	/// Reset the hash function
	/// </summary>
	void Reset();

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

	static void Permute(std::array<ulong, CMUL::CMUL_STATE_SIZE> &State, std::vector<byte> &Output);
	static bool HasGmul();
};

NAMESPACE_DIGESTEND
#endif
