#ifndef _CEX_RLWEPARAMSET_H
#define _CEX_RLWEPARAMSET_H

#include "CexDomain.h"

NAMESPACE_RINGLWE

/// <summary>
/// RingLWE parameter settings
/// </summary>
struct RLWEParamSet
{
	/// <summary>
	/// The number of coefficients
	/// </summary>
	size_t N;

	/// <summary>
	/// The modulus factor
	/// </summary>
	int Q;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	size_t SeedSize;

	/// <summary>
	/// The byte size of A's forward message to host B
	/// </summary>
	size_t ForwardMessageSize;

	/// <summary>
	/// The parameter sets formal name
	/// </summary>
	std::string Name;

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	size_t ReturnMessageSize;

	/// <summary>
	/// Empty constructor
	/// </summary>
	RLWEParamSet()
		:
		N(0),
		Q(0),
		ForwardMessageSize(0),
		Name(""),
		ReturnMessageSize(0),
		SeedSize(0)
	{}

	/// <summary>
	/// Finalize state
	/// </summary>
	~RLWEParamSet()
	{
		Reset();
	}

	/// <summary>
	/// Load the parameter values
	/// </summary>
	/// <param name="Coefficients">The number of coefficients N</param>
	/// <param name="Modulus">The modulus factor Q</param>
	/// <param name="SeedByteSize">The byte size of the secret seed array</param>
	/// <param name="ForwardByteSize">The byte size of A's forward message to host B</param>
	/// <param name="ReturnByteSize">The byte size of B's reply message to host A</param>
	/// <param name="ParamName">The parameter sets formal name</param>
	void Load(size_t Coefficients, int Modulus, size_t SeedByteSize, size_t ForwardByteSize, size_t ReturnByteSize, std::string ParamName)
	{
		N = Coefficients;
		Q = Modulus;
		ForwardMessageSize = ForwardByteSize;
		Name = ParamName;
		ReturnMessageSize = ReturnByteSize;
		SeedSize = SeedByteSize;
	}

	/// <summary>
	/// Reset current parameters
	/// </summary>
	void Reset()
	{
		N = 0;
		Q = 0;
		ForwardMessageSize = 0;
		Name = "";
		ReturnMessageSize = 0;
		SeedSize = 0;
	}
};

NAMESPACE_RINGLWEEND
#endif