#ifndef _CEX_RLWEPARAMSET_H
#define _CEX_RLWEPARAMSET_H

#include "CexDomain.h"

NAMESPACE_RINGLWE

/// <summary>
/// The RingLWE parameter set
/// </summary>
struct RLWEParamSet
{
public:

	int FWD_CONST1;
	int FWD_CONST2;
	int HAMMING_TABLE_SIZE;
	int INVCONST1;
	int INVCONST2;
	int INVCONST3;
	int KN_DISTANCE1_MASK;
	int KN_DISTANCE2_MASK;
	int N;
	int PMAT_MAX_COL;
	int Q;
	int QBY2;
	int QBY4;
	int QBY4_TIMES3;
	int SCALING;

	std::vector<ushort> PrimeRtOmegaTable;
	std::vector<ushort> PrimeRtInvOmegaTable;
	std::vector<byte> Lut1;
	std::vector<byte> Lut2;
	std::vector<uint> PmatColsSmallLow;
	std::vector<uint> PmatColsSmallHigh;
};

NAMESPACE_RINGLWEEND
#endif