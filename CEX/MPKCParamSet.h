#ifndef _CEX_MPKCPARAMSET_H
#define _CEX_MPKCPARAMSET_H

#include "CexDomain.h"

NAMESPACE_MCELIECE

/// <summary>
/// McEliece parameter settings
/// </summary>
struct MPKCParamSet
{

	/// <summary>
	/// The finite field GF(2^m)
	/// </summary>
	int GF;

	/// <summary>
	/// The error correction capability of the code
	/// </summary>
	int T;

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
	MPKCParamSet()
		:
		GF(0),
		T(0),
		ForwardMessageSize(0),
		Name(""),
		ReturnMessageSize(0),
		SeedSize(0)
	{}

	/// <summary>
	/// Finalize state
	/// </summary>
	~MPKCParamSet()
	{
		Reset();
	}

	/// <summary>
	/// Load the parameter values
	/// </summary>
	/// <param name="Gf">The finite field GF(2^m)</param>
	/// <param name="T">The error correction capability of the code</param>
	/// <param name="SeedByteSize">The byte size of the secret seed array</param>
	/// <param name="ForwardByteSize">The byte size of A's forward message to host B</param>
	/// <param name="ReturnByteSize">The byte size of B's reply message to host A</param>
	/// <param name="ParamName">The parameter sets formal name</param>
	void Load(int Field, int Correction, size_t SeedByteSize, size_t ForwardByteSize, size_t ReturnByteSize, std::string ParamName)
	{
		GF = Field;
		T = Correction;
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
		GF = 0;
		T = 0;
		ForwardMessageSize = 0;
		Name = "";
		ReturnMessageSize = 0;
		SeedSize = 0;
	}
};

NAMESPACE_MCELIECEEND
#endif