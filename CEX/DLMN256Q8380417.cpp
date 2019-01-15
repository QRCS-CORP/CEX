#include "DLMN256Q8380417.h"

NAMESPACE_DILITHIUM

const std::array<uint, 256> DLMN256Q8380417::Zetas = { 0, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868, 6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005, 2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439, 4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596, 811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892, 5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196, 7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922, 3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370, 7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987, 5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618, 4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561, 189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330, 1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961, 2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955, 266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039, 900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917, 7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579, 342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044, 2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974, 4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447, 7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775, 7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136, 4603424, 6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032, 5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310, 5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078, 7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524, 5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782 };

const std::array<uint, 256> DLMN256Q8380417::ZetasInv = { 6403635, 846154, 6979993, 4442679, 1362209, 48306, 4460757, 554416, 3545687, 6767575, 976891, 8196974, 2286327, 420899, 2235985, 2939036, 3833893, 260646, 1104333, 1667432, 6470041, 1803090, 6656817, 426683, 7908339, 6662682, 975884, 6167306, 8110657, 4513516, 4856520, 3038916, 1799107, 3694233, 6727783, 7570268, 5366416, 6764025, 8217573, 3183426, 1207385, 8194886, 5011305, 6423145, 164721, 5925962, 5948022, 2013608, 3776993, 7786281, 3724270, 2584293, 1846953, 1671176, 2831860, 542412, 4974386, 6144537, 7603226, 6880252, 1374803, 2546312, 6463336, 1279661, 1962642, 5074302, 7067962, 451100, 1430225, 3318210, 7143142, 1333058, 1050970, 6476982, 6511298, 2994039, 3548272, 5744496, 7129923, 3767016, 6784443, 5894064, 7132797, 4325093, 7115408, 2590150, 5688936, 5538076, 8177373, 6644538, 3342277, 4943130, 4272102, 2437823, 8093429, 8038120, 3595838, 768622, 525098, 3556995, 5173371, 6348669, 3122442, 655327, 522500, 43260, 1613174, 7884926, 7561383, 7470875, 6521319, 7479715, 3193378, 1197226, 3759364, 3520352, 4867236, 1235728, 5945978, 8113420, 3562462, 2446433, 6136326, 3342478, 4562441, 6063917, 4972711, 6288750, 4540456, 3628969, 3881060, 3019102, 1439742, 812732, 1584928, 7094748, 7039087, 7064828, 177440, 2409325, 1851402, 5220671, 3553272, 8190869, 1316856, 7620448, 210977, 5991061, 3249728, 6727353, 8578, 3724342, 4421799, 7475901, 1100098, 8336129, 5282425, 7871466, 8115473, 3343383, 1430430, 6527646, 7031341, 381987, 1308169, 22981, 1228525, 671102, 2477047, 411027, 3693493, 2967645, 5665122, 6232521, 983419, 4968207, 8253495, 3632928, 3157330, 3190144, 1000202, 4083598, 6441103, 1257611, 1585221, 6203962, 4904467, 1452451, 3041255, 3677745, 1528703, 3930395, 2797779, 6308525, 2556880, 4479693, 4499374, 7426187, 7849063, 7568473, 4680821, 1600420, 2140649, 4873154, 3821735, 4874723, 1643818, 1699267, 539299, 6031717, 300467, 4840449, 2867647, 4805995, 3043716, 3861115, 4464978, 2537516, 3592148, 1661693, 4849980, 5303092, 8284641, 5674394, 8100412, 4369920, 19422, 6623180, 3277672, 1399561, 3859737, 2118186, 2108549, 5760665, 1119584, 549488, 4794489, 1079900, 7356305, 5654953, 5700314, 5268920, 2884855, 5260684, 2091905, 359251, 6026966, 6554070, 7913949, 876248, 777960, 8143293, 518909, 2608894, 8354570 };

void DLMN256Q8380417::Challenge(Poly &C, const std::vector<byte> &Mu, const PolyVec &W1)
{
	const size_t NK = W1.vec.size();
	std::vector<byte> buffer(SHAKE256_BLOCKSIZE);
	std::vector<byte> tmps(CRHBYTES + NK * POLW1_SIZE_PACKED);
	ulong mask;
	ulong signs;
	size_t i;
	size_t j;
	size_t k;

	MemoryTools::Copy(Mu, 0, tmps, 0, CRHBYTES);

	for (i = 0; i < NK; ++i)
	{
		PolyW1Pack(tmps, CRHBYTES + (i * POLW1_SIZE_PACKED), W1.vec[i]);
	}

	SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(tmps);
	gen.Generate(buffer);

	signs = 0;
	for (i = 0; i < 8; ++i)
	{
		signs |= static_cast<ulong>(buffer[i]) << (8 * i);
	}

	j = 8;
	mask = 1;
	MemoryTools::Clear(C.coeffs, 0, C.coeffs.size() * sizeof(uint));

	for (i = 196; i < N; ++i)
	{
		do
		{
			if (j >= SHAKE256_BLOCKSIZE)
			{
				gen.Generate(buffer);
				j = 0;
			}

			k = static_cast<size_t>(buffer[j]);
			++j;
		} while (k > i);

		C.coeffs[i] = C.coeffs[k];
		C.coeffs[k] = (signs & mask) ? Q - 1 : 1;
		mask <<= 1;
	}
}

uint DLMN256Q8380417::CSubQ(uint A)
{
	A -= Q;
	A += (static_cast<int32_t>(A) >> 31) & Q;

	return A;
}

uint DLMN256Q8380417::Decompose(uint A, uint &A0)
{
	int32_t t;
	int32_t u;

	// centralized remainder mod ALPHA
	t = A & 0x7FFFFUL;
	t += (A >> 19) << 9;
	t -= (ALPHA / 2) + 1;
	t += (t >> 31) & ALPHA;
	t -= (ALPHA / 2) - 1;
	A -= t;
	// divide by ALPHA (possible to avoid)
	u = A - 1;
	u >>= 31;
	A = (A >> 19) + 1;
	A -= u & 1;
	// border case
	A0 = (Q + t) - (A >> 4);
	A &= 0x0F;

	return A;
}

void DLMN256Q8380417::ExpandMatrix(std::vector<PolyVec> &Mat, const std::vector<byte> &Rho)
{
	// don't change this to smaller values,
	// sampling later assumes sufficient SHAKE output!
	// probability that we need more than 5 blocks: < 2^{-132}
	// probability that we need more than 6 blocks: < 2^{-546}

	std::vector<byte> buf(5 * SHAKE128_BLOCKSIZE);
	std::vector<byte> seed(SEEDBYTES + 1);
	size_t i;
	size_t j;

	MemoryTools::Copy(Rho, 0, seed, 0, SEEDBYTES);
	SHAKE gen(Enumeration::ShakeModes::SHAKE128);

	for (i = 0; i < Mat.size(); ++i)
	{
		for (j = 0; j < Mat[0].vec.size(); ++j)
		{
			seed[SEEDBYTES] = static_cast<byte>(i + (j << 4));
			gen.Initialize(seed);
			gen.Generate(buf);
			PolyUniform(Mat[i].vec[j], buf);
		}
	}
}

uint DLMN256Q8380417::Freeze(uint A)
{
	A = Reduce32(A);
	A = CSubQ(A);

	return A;
}

void DLMN256Q8380417::InvNttFromInvMont(std::array<uint, N> &P)
{
	const ulong F = ((static_cast<ulong>(MONT) * MONT % Q) * (Q - 1) % Q) * ((Q - 1) >> 8) % Q;
	size_t j;
	size_t k;
	size_t len;
	size_t start;
	uint t;
	uint zeta;

	j = 0;
	k = 0;

	for (len = 1; len < N; len <<= 1)
	{
		for (start = 0; start < N; start = j + len)
		{
			zeta = ZetasInv[k];
			++k;
			for (j = start; j < start + len; ++j)
			{
				t = P[j];
				P[j] = t + P[j + len];
				P[j + len] = t + 256 * Q - P[j + len];
				P[j + len] = MontgomeryReduce(static_cast<ulong>(zeta) * P[j + len]);
			}
		}
	}

	for (j = 0; j < N; ++j)
	{
		P[j] = MontgomeryReduce(F * P[j]);
	}
}

uint DLMN256Q8380417::MakeHint(const uint A, const uint B)
{
	uint t;

	return Decompose(A, t) != Decompose(B, t);
}

uint DLMN256Q8380417::MontgomeryReduce(ulong A)
{
	ulong t;

	t = A * QINV;
	t &= (1ULL << 32) - 1;
	t *= Q;
	t = A + t;
	t >>= 32;

	return t;
}

void DLMN256Q8380417::Ntt(Poly &P)
{
	size_t j;
	size_t k;
	size_t len;
	size_t start;
	uint t;
	uint zeta;

	j = 0;
	k = 1;

	for (len = 128; len > 0; len >>= 1)
	{
		for (start = 0; start < N; start = j + len)
		{
			zeta = Zetas[k];
			++k;
			for (j = start; j < start + len; ++j)
			{
				t = MontgomeryReduce(static_cast<ulong>(zeta) * P.coeffs[j + len]);
				P.coeffs[j + len] = P.coeffs[j] + 2 * Q - t;
				P.coeffs[j] = P.coeffs[j] + t;
			}
		}
	}
}

void DLMN256Q8380417::PackPk(std::vector<byte> &Pk, const std::vector<byte> Rho, const PolyVec &T1)
{
	const size_t NK = T1.vec.size();
	size_t i;

	MemoryTools::Copy(Rho, 0, Pk, 0, SEEDBYTES);

	for (i = 0; i < NK; ++i)
	{
		PolyT1Pack(Pk, SEEDBYTES + (i * POLT1_SIZE_PACKED), T1.vec[i]);
	}
}

void DLMN256Q8380417::PackSig(std::vector<byte> &Signature, const PolyVec &Z, const PolyVec &H, const Poly &C, uint Omega)
{
	const size_t NK = H.vec.size();
	const size_t NL = Z.vec.size();
	ulong mask;
	ulong signs;
	size_t i;
	size_t j;
	size_t k;
	size_t sigoff;

	for (i = 0; i < NL; ++i)
	{
		PolyZPack(Signature, i * POLZ_SIZE_PACKED, Z.vec[i]);
	}

	// encode h
	sigoff = NL * POLZ_SIZE_PACKED;
	k = 0;

	for (i = 0; i < NK; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if (H.vec[i].coeffs[j] != 0)
			{
				Signature[sigoff + k] = static_cast<byte>(j);
				++k;
			}
		}

		Signature[sigoff + Omega + i] = static_cast<byte>(k);
	}

	while (k < Omega)
	{
		Signature[sigoff + k] = 0;
		++k;
	}

	sigoff += Omega + NK;

	// encode c
	signs = 0;
	mask = 1;

	for (i = 0; i < N / 8; ++i)
	{
		Signature[sigoff + i] = 0;

		for (j = 0; j < 8; ++j)
		{
			if (C.coeffs[8 * i + j] != 0)
			{
				Signature[sigoff + i] |= (1U << j);
				if (C.coeffs[8 * i + j] == (Q - 1))
				{
					signs |= mask;
				}
				mask <<= 1;
			}
		}
	}

	sigoff += N / 8;

	for (i = 0; i < 8; ++i)
	{
		Signature[sigoff + i] = signs >> 8 * i;
	}
}

void DLMN256Q8380417::PackSk(std::vector<byte> &Sk, const std::vector<byte> &Rho, const std::vector<byte> &Key, const std::vector<byte> &Tr, const PolyVec &S1, const PolyVec &S2, const PolyVec &T0, uint Eta, size_t EtaPack)
{
	const size_t NK = S2.vec.size();
	const size_t NL = S1.vec.size();
	size_t i;
	size_t skoft;

	MemoryTools::Copy(Rho, 0, Sk, 0, SEEDBYTES);
	skoft = SEEDBYTES;
	MemoryTools::Copy(Key, 0, Sk, skoft, SEEDBYTES);
	skoft += SEEDBYTES;
	MemoryTools::Copy(Tr, 0, Sk, skoft, CRHBYTES);
	skoft += CRHBYTES;

	for (i = 0; i < NL; ++i)
	{
		PolyEtaPack(Sk, skoft + (i * EtaPack), S1.vec[i], Eta);
	}
	skoft += NL * EtaPack;

	for (i = 0; i < NK; ++i)
	{
		PolyEtaPack(Sk, skoft + (i * EtaPack), S2.vec[i], Eta);
	}
	skoft += NK * EtaPack;

	for (i = 0; i < NK; ++i)
	{
		PolyT0Pack(Sk, skoft + (i * POLT0_SIZE_PACKED), T0.vec[i]);
	}
}

void DLMN256Q8380417::PolyAdd(Poly &C, const Poly &A, const Poly &B)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		C.coeffs[i] = A.coeffs[i] + B.coeffs[i];
	}
}

int32_t DLMN256Q8380417::PolyChkNorm(const Poly &A, uint B)
{
	size_t i;
	int32_t t;

	// it is ok to leak which coefficient violates the bound since
	// the probability for each coefficient is independent of secret
	// data but we must not leak the sign of the centralized representative
	for (i = 0; i < N; ++i)
	{
		// absolute value of centralized representative
		t = ((Q - 1) / 2) - A.coeffs[i];
		t ^= (t >> 31);
		t = ((Q - 1) / 2) - t;

		if (static_cast<uint>(t) >= B)
		{
			return 1;
		}
	}

	return 0;
}

void DLMN256Q8380417::PolyCSubq(Poly &A)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		A.coeffs[i] = CSubQ(A.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyDecompose(Poly &A1, Poly &A0, const Poly &A)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		A1.coeffs[i] = Decompose(A.coeffs[i], A0.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyEtaPack(std::vector<byte> &R, size_t ROffset, const Poly &A, uint Eta)
{
	std::array<byte, 8> t;
	size_t i;

	if (Eta <= 3)
	{
		for (i = 0; i < N / 8; ++i)
		{
			t[0] = Q + Eta - A.coeffs[(8 * i)];
			t[1] = Q + Eta - A.coeffs[(8 * i) + 1];
			t[2] = Q + Eta - A.coeffs[(8 * i) + 2];
			t[3] = Q + Eta - A.coeffs[(8 * i) + 3];
			t[4] = Q + Eta - A.coeffs[(8 * i) + 4];
			t[5] = Q + Eta - A.coeffs[(8 * i) + 5];
			t[6] = Q + Eta - A.coeffs[(8 * i) + 6];
			t[7] = Q + Eta - A.coeffs[(8 * i) + 7];

			R[ROffset + (3 * i)] = t[0];
			R[ROffset + (3 * i)] |= t[1] << 3;
			R[ROffset + (3 * i)] |= t[2] << 6;
			R[ROffset + (3 * i) + 1] = t[2] >> 2;
			R[ROffset + (3 * i) + 1] |= t[3] << 1;
			R[ROffset + (3 * i) + 1] |= t[4] << 4;
			R[ROffset + (3 * i) + 1] |= t[5] << 7;
			R[ROffset + (3 * i) + 2] = t[5] >> 1;
			R[ROffset + (3 * i) + 2] |= t[6] << 2;
			R[ROffset + (3 * i) + 2] |= t[7] << 5;
		}
	}
	else
	{
		for (i = 0; i < N / 2; ++i)
		{
			t[0] = Q + Eta - A.coeffs[(2 * i)];
			t[1] = Q + Eta - A.coeffs[(2 * i) + 1];
			R[ROffset + i] = t[0] | (t[1] << 4);
		}
	}
}

void DLMN256Q8380417::PolyEtaUnpack(Poly &R, const std::vector<byte> &A, size_t AOffset, uint Eta)
{
	size_t i;

	if (Eta <= 3) 
	{
		for (i = 0; i < N / 8; ++i)
		{
			R.coeffs[(8 * i)] = A[(3 * i) + AOffset] & 0x07;
			R.coeffs[(8 * i) + 1] = (A[(3 * i) + AOffset] >> 3) & 0x07;
			R.coeffs[(8 * i) + 2] = (A[(3 * i) + AOffset] >> 6) | ((A[(3 * i) + AOffset + 1] & 0x01) << 2);
			R.coeffs[(8 * i) + 3] = (A[(3 * i) + AOffset + 1] >> 1) & 0x07;
			R.coeffs[(8 * i) + 4] = (A[(3 * i) + AOffset + 1] >> 4) & 0x07;
			R.coeffs[(8 * i) + 5] = (A[(3 * i) + AOffset + 1] >> 7) | ((A[(3 * i) + AOffset + 2] & 0x03) << 1);
			R.coeffs[(8 * i) + 6] = (A[(3 * i) + AOffset + 2] >> 2) & 0x07;
			R.coeffs[(8 * i) + 7] = (A[(3 * i) + AOffset + 2] >> 5);

			R.coeffs[(8 * i)] = Q + Eta - R.coeffs[(8 * i)];
			R.coeffs[(8 * i) + 1] = Q + Eta - R.coeffs[(8 * i) + 1];
			R.coeffs[(8 * i) + 2] = Q + Eta - R.coeffs[(8 * i) + 2];
			R.coeffs[(8 * i) + 3] = Q + Eta - R.coeffs[(8 * i) + 3];
			R.coeffs[(8 * i) + 4] = Q + Eta - R.coeffs[(8 * i) + 4];
			R.coeffs[(8 * i) + 5] = Q + Eta - R.coeffs[(8 * i) + 5];
			R.coeffs[(8 * i) + 6] = Q + Eta - R.coeffs[(8 * i) + 6];
			R.coeffs[(8 * i) + 7] = Q + Eta - R.coeffs[(8 * i) + 7];
		}
	}
	else
	{
		for (i = 0; i < N / 2; ++i)
		{
			R.coeffs[(2 * i)] = A[AOffset + i] & 0x0F;
			R.coeffs[(2 * i) + 1] = A[AOffset + i] >> 4;
			R.coeffs[(2 * i)] = Q + Eta - R.coeffs[(2 * i)];
			R.coeffs[(2 * i) + 1] = Q + Eta - R.coeffs[(2 * i) + 1];
		}
	}
}

void DLMN256Q8380417::PolyFreeze(Poly &A)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		A.coeffs[i] = Freeze(A.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyInvNttMontgomery(Poly &A)
{
	InvNttFromInvMont(A.coeffs);
}

uint DLMN256Q8380417::PolyMakeHint(Poly &H, const Poly &A, const Poly &B)
{
	size_t i;
	uint s;

	s = 0;

	for (i = 0; i < N; ++i)
	{
		H.coeffs[i] = MakeHint(A.coeffs[i], B.coeffs[i]);
		s += H.coeffs[i];
	}

	return s;
}

void DLMN256Q8380417::PolyNtt(Poly &A)
{
	Ntt(A);
}

void DLMN256Q8380417::PolyPointwiseInvMontgomery(Poly &C, const Poly &A, const Poly &B)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		C.coeffs[i] = MontgomeryReduce(static_cast<ulong>(A.coeffs[i]) * B.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyPower2Round(Poly &A1, Poly &A0, const Poly &A)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		A1.coeffs[i] = Power2Round(A.coeffs[i], A0.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyReduce(Poly &A)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		A.coeffs[i] = Reduce32(A.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyShiftL(Poly &A, uint Shift)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		A.coeffs[i] <<= Shift;
	}
}

void DLMN256Q8380417::PolySub(Poly &C, const Poly &A, const Poly &B)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		C.coeffs[i] = A.coeffs[i] + (2 * Q) - B.coeffs[i];
	}
}

void DLMN256Q8380417::PolyT0Pack(std::vector<byte> &R, size_t ROffset, const Poly &A)
{
	std::array<uint, 4> t;
	size_t i;

	for (i = 0; i < N / 4; ++i)
	{
		t[0] = Q + (1 << (D - 1)) - A.coeffs[(4 * i)];
		t[1] = Q + (1 << (D - 1)) - A.coeffs[(4 * i) + 1];
		t[2] = Q + (1 << (D - 1)) - A.coeffs[(4 * i) + 2];
		t[3] = Q + (1 << (D - 1)) - A.coeffs[(4 * i) + 3];

		R[(7 * i) + ROffset] = t[0];
		R[(7 * i) + ROffset + 1] = t[0] >> 8;
		R[(7 * i) + ROffset + 1] |= t[1] << 6;
		R[(7 * i) + ROffset + 2] = t[1] >> 2;
		R[(7 * i) + ROffset + 3] = t[1] >> 10;
		R[(7 * i) + ROffset + 3] |= t[2] << 4;
		R[(7 * i) + ROffset + 4] = t[2] >> 4;
		R[(7 * i) + ROffset + 5] = t[2] >> 12;
		R[(7 * i) + ROffset + 5] |= t[3] << 2;
		R[(7 * i) + ROffset + 6] = t[3] >> 6;
	}
}

void DLMN256Q8380417::PolyT0Unpack(Poly &R, const std::vector<byte> &A, size_t AOffset)
{
	size_t i;

	for (i = 0; i < N / 4; ++i)
	{
		R.coeffs[(4 * i)] = A[(7 * i) + AOffset];
		R.coeffs[(4 * i)] |= static_cast<uint>(A[(7 * i) + AOffset + 1] & 0x3F) << 8;
		R.coeffs[(4 * i) + 1] = A[(7 * i) + AOffset + 1] >> 6;
		R.coeffs[(4 * i) + 1] |= static_cast<uint>(A[(7 * i) + AOffset + 2]) << 2;
		R.coeffs[(4 * i) + 1] |= static_cast<uint>(A[(7 * i) + AOffset + 3] & 0x0F) << 10;
		R.coeffs[(4 * i) + 2] = A[(7 * i) + AOffset + 3] >> 4;
		R.coeffs[(4 * i) + 2] |= static_cast<uint>(A[(7 * i) + AOffset + 4]) << 4;
		R.coeffs[(4 * i) + 2] |= static_cast<uint>(A[(7 * i) + AOffset + 5] & 0x03) << 12;
		R.coeffs[(4 * i) + 3] = A[(7 * i) + AOffset + 5] >> 2;
		R.coeffs[(4 * i) + 3] |= static_cast<uint>(A[(7 * i) + AOffset + 6]) << 6;
		R.coeffs[(4 * i)] = Q + (1 << (D - 1)) - R.coeffs[(4 * i)];
		R.coeffs[(4 * i) + 1] = Q + (1 << (D - 1)) - R.coeffs[(4 * i) + 1];
		R.coeffs[(4 * i) + 2] = Q + (1 << (D - 1)) - R.coeffs[(4 * i) + 2];
		R.coeffs[(4 * i) + 3] = Q + (1 << (D - 1)) - R.coeffs[(4 * i) + 3];
	}
}

void DLMN256Q8380417::PolyT1Pack(std::vector<byte> &R, size_t ROffset, const Poly &A)
{
	size_t i;

	for (i = 0; i < N / 8; ++i)
	{
		R[(9 * i) + ROffset] = A.coeffs[(8 * i)] & 0xFF;
		R[(9 * i) + ROffset + 1] = (A.coeffs[(8 * i)] >> 8) | ((A.coeffs[(8 * i) + 1] & 0x7F) << 1);
		R[(9 * i) + ROffset + 2] = (A.coeffs[(8 * i) + 1] >> 7) | ((A.coeffs[(8 * i) + 2] & 0x3F) << 2);
		R[(9 * i) + ROffset + 3] = (A.coeffs[(8 * i) + 2] >> 6) | ((A.coeffs[(8 * i) + 3] & 0x1F) << 3);
		R[(9 * i) + ROffset + 4] = (A.coeffs[(8 * i) + 3] >> 5) | ((A.coeffs[(8 * i) + 4] & 0x0F) << 4);
		R[(9 * i) + ROffset + 5] = (A.coeffs[(8 * i) + 4] >> 4) | ((A.coeffs[(8 * i) + 5] & 0x07) << 5);
		R[(9 * i) + ROffset + 6] = (A.coeffs[(8 * i) + 5] >> 3) | ((A.coeffs[(8 * i) + 6] & 0x03) << 6);
		R[(9 * i) + ROffset + 7] = (A.coeffs[(8 * i) + 6] >> 2) | ((A.coeffs[(8 * i) + 7] & 0x01) << 7);
		R[(9 * i) + ROffset + 8] = A.coeffs[(8 * i) + 7] >> 1;
	}
}

void DLMN256Q8380417::PolyT1Unpack(Poly &R, const std::vector<byte> &A, size_t AOffset)
{
	size_t i;

	for (i = 0; i < N / 8; ++i)
	{
		R.coeffs[(8 * i)] = A[(9 * i) + AOffset] | (static_cast<uint>(A[(9 * i) + AOffset + 1] & 0x01) << 8);
		R.coeffs[(8 * i) + 1] = (A[(9 * i) + AOffset + 1] >> 1) | (static_cast<uint>(A[(9 * i) + AOffset + 2] & 0x03) << 7);
		R.coeffs[(8 * i) + 2] = (A[(9 * i) + AOffset + 2] >> 2) | (static_cast<uint>(A[(9 * i) + AOffset + 3] & 0x07) << 6);
		R.coeffs[(8 * i) + 3] = (A[(9 * i) + AOffset + 3] >> 3) | (static_cast<uint>(A[(9 * i) + AOffset + 4] & 0x0F) << 5);
		R.coeffs[(8 * i) + 4] = (A[(9 * i) + AOffset + 4] >> 4) | (static_cast<uint>(A[(9 * i) + AOffset + 5] & 0x1F) << 4);
		R.coeffs[(8 * i) + 5] = (A[(9 * i) + AOffset + 5] >> 5) | (static_cast<uint>(A[(9 * i) + AOffset + 6] & 0x3F) << 3);
		R.coeffs[(8 * i) + 6] = (A[(9 * i) + AOffset + 6] >> 6) | (static_cast<uint>(A[(9 * i) + AOffset + 7] & 0x7F) << 2);
		R.coeffs[(8 * i) + 7] = (A[(9 * i) + AOffset + 7] >> 7) | (static_cast<uint>(A[(9 * i) + AOffset + 8] & 0xFF) << 1);
	}
}

void DLMN256Q8380417::PolyUniform(Poly &A, const std::vector<byte> &Input)
{
	size_t ctr;
	size_t pos;
	uint t;

	ctr = 0;
	pos = 0;

	while (ctr < N)
	{
		t = Input[pos];
		++pos;
		t |= static_cast<uint>(Input[pos]) << 8;
		++pos;
		t |= static_cast<uint>(Input[pos]) << 16;
		++pos;
		t &= 0x7FFFFFUL;

		if (t < Q)
		{
			A.coeffs[ctr] = t;
			++ctr;
		}
	}
}

void DLMN256Q8380417::PolyUniformEta(Poly &A, const std::vector<byte> &Seed, byte Nonce, uint Eta)
{
	// probability that we need more than 2 blocks: < 2^{-84}, 3 blocks: < 2^{-352}

	std::vector<byte> tmps(SEEDBYTES + 1);
	std::vector<byte> buf(SHAKE256_BLOCKSIZE * 2);
	uint ctr;

	SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	MemoryTools::Copy(Seed, 0, tmps, 0, SEEDBYTES);

	tmps[SEEDBYTES] = Nonce;
	gen.Initialize(tmps);
	gen.Generate(buf);
	ctr = RejEta(A.coeffs, 0, N, buf, buf.size(), Eta);

	if (ctr < N)
	{
		gen.Generate(buf, 0, 136);
		RejEta(A.coeffs, ctr, N - ctr, buf, SHAKE256_BLOCKSIZE, Eta);
	}
}

void DLMN256Q8380417::PolyUniformGamma1M1(Poly &A, const std::vector<byte> &Seed, const std::vector<byte> &Mu, ushort Nonce)
{
	// probability that we need more than 5 blocks: < 2^{-81}
	// probability that we need more than 6 blocks: < 2^{-467}

	std::vector<byte> buffer(5 * SHAKE256_BLOCKSIZE);
	std::vector<byte> tmps(SEEDBYTES + CRHBYTES + 2);
	uint ctr;

	MemoryTools::Copy(Seed, 0, tmps, 0, SEEDBYTES);
	MemoryTools::Copy(Mu, 0, tmps, SEEDBYTES, CRHBYTES);

	tmps[SEEDBYTES + CRHBYTES] = Nonce & 0xFF;
	tmps[SEEDBYTES + CRHBYTES + 1] = Nonce >> 8;

	SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(tmps);
	gen.Generate(buffer);
	ctr = RejGamma1M1(A.coeffs, 0, N, buffer);

	if (ctr < N)
	{
		// there are no bytes left in outbuf since 5 * SHAKE256_BLOCKSIZE is divisible by 5
		gen.Generate(buffer, 0, SHAKE256_BLOCKSIZE);
		RejGamma1M1(A.coeffs, ctr, N - ctr, buffer);
	}
}

void DLMN256Q8380417::PolyUseHint(Poly &A, const Poly &B, const Poly &H)
{
	size_t i;

	for (i = 0; i < N; ++i)
	{
		A.coeffs[i] = UseHint(B.coeffs[i], H.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyW1Pack(std::vector<byte> &R, size_t ROffset, const Poly &A)
{
	size_t i;

	for (i = 0; i < N / 2; ++i)
	{
		R[ROffset + i] = A.coeffs[(2 * i)] | (A.coeffs[(2 * i) + 1] << 4);
	}
}

void DLMN256Q8380417::PolyZPack(std::vector<byte> &R, size_t ROffset, const Poly &A)
{
	std::array<uint, 2> t;
	size_t i;

	for (i = 0; i < N / 2; ++i)
	{
		// map to {0,...,2*GAMMA1 - 2}
		t[0] = GAMMA1 - 1 - A.coeffs[(2 * i)];
		t[0] += (static_cast<int32_t>(t[0]) >> 31) & Q;
		t[1] = GAMMA1 - 1 - A.coeffs[(2 * i) + 1];
		t[1] += (static_cast<int32_t>(t[1]) >> 31) & Q;

		R[(5 * i) + ROffset] = t[0];
		R[(5 * i) + ROffset + 1] = t[0] >> 8;
		R[(5 * i) + ROffset + 2] = t[0] >> 16;
		R[(5 * i) + ROffset + 2] |= t[1] << 4;
		R[(5 * i) + ROffset + 3] = t[1] >> 4;
		R[(5 * i) + ROffset + 4] = t[1] >> 12;
	}
}

void DLMN256Q8380417::PolyZUnpack(Poly &R, const std::vector<byte> &A, size_t AOffset)
{
	size_t i;

	for (i = 0; i < N / 2; ++i)
	{
		R.coeffs[(2 * i)] = A[(5 * i) + AOffset];
		R.coeffs[(2 * i)] |= static_cast<uint>(A[(5 * i) + AOffset + 1]) << 8;
		R.coeffs[(2 * i)] |= static_cast<uint>(A[(5 * i) + AOffset + 2] & 0x0F) << 16;
		R.coeffs[(2 * i) + 1] = A[(5 * i) + AOffset + 2] >> 4;
		R.coeffs[(2 * i) + 1] |= static_cast<uint>(A[(5 * i) + AOffset + 3]) << 4;
		R.coeffs[(2 * i) + 1] |= static_cast<uint>(A[(5 * i) + AOffset + 4]) << 12;
		R.coeffs[(2 * i)] = GAMMA1 - 1 - R.coeffs[(2 * i)];
		R.coeffs[(2 * i)] += (static_cast<int32_t>(R.coeffs[(2 * i)]) >> 31) & Q;
		R.coeffs[(2 * i) + 1] = GAMMA1 - 1 - R.coeffs[(2 * i) + 1];
		R.coeffs[(2 * i) + 1] += (static_cast<int32_t>(R.coeffs[(2 * i) + 1]) >> 31) & Q;
	}
}

uint DLMN256Q8380417::Power2Round(uint A, uint &A0)
{
	int32_t t;

	// centralized remainder mod 2^D
	t = A & ((1 << D) - 1);
	t -= (1 << (D - 1)) + 1;
	t += (t >> 31) & (1 << D);
	t -= (1 << (D - 1)) - 1;
	A0 = Q + t;
	A = (A - t) >> D;

	return A;
}

uint DLMN256Q8380417::Reduce32(uint A)
{
	uint t;

	t = A & 0x7FFFFFUL;
	A >>= 23;
	t += (A << 13) - A;

	return t;
}

uint DLMN256Q8380417::RejEta(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Input, size_t InLength, uint Eta)
{
	size_t pos;
	uint ctr;
	byte t0;
	byte t1;

	ctr = 0;
	pos = 0;

	while (ctr < ALength && pos < InLength)
	{
		if (Eta <= 3)
		{
			t0 = Input[pos] & 0x07;
			t1 = Input[pos] >> 5;
			++pos;
		}
		else
		{
			t0 = Input[pos] & 0x0F;
			t1 = Input[pos] >> 4;
			++pos;
		}

		if (t0 <= 2 * Eta)
		{
			A[AOffset + ctr] = Q + Eta - t0;
			++ctr;
		}
		if (t1 <= 2 * Eta && ctr < ALength)
		{
			A[AOffset + ctr] = Q + Eta - t1;
			++ctr;
		}
	}

	return ctr;
}

uint DLMN256Q8380417::RejGamma1M1(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Buffer)
{
	size_t pos;
	uint ctr;
	uint t0;
	uint t1;

	ctr = 0;
	pos = 0;

	while (ctr < ALength && pos + 5 <= Buffer.size())
	{
		t0 = Buffer[pos];
		t0 |= static_cast<uint>(Buffer[pos + 1]) << 8;
		t0 |= static_cast<uint>(Buffer[pos + 2]) << 16;
		t0 &= 0xFFFFFUL;

		t1 = Buffer[pos + 2] >> 4;
		t1 |= static_cast<uint>(Buffer[pos + 3]) << 4;
		t1 |= static_cast<uint>(Buffer[pos + 4]) << 12;

		pos += 5;

		if (t0 <= (2 * GAMMA1) - 2)
		{
			A[AOffset + ctr] = Q + GAMMA1 - 1 - t0;
			++ctr;
		}
		if (t1 <= (2 * GAMMA1) - 2 && ctr < ALength)
		{
			A[AOffset + ctr] = Q + GAMMA1 - 1 - t1;
			++ctr;
		}
	}

	return ctr;
}

void DLMN256Q8380417::UnPackPk(std::vector<byte> &Rho, PolyVec &T1, const std::vector<byte> &Pk)
{
	const size_t NK = T1.vec.size();
	size_t i;

	MemoryTools::Copy(Pk, 0, Rho, 0, SEEDBYTES);

	for (i = 0; i < NK; ++i)
	{
		PolyT1Unpack(T1.vec[i], Pk, SEEDBYTES + (i * POLT1_SIZE_PACKED));
	}
}

int32_t DLMN256Q8380417::UnPackSig(PolyVec &Z, PolyVec &H, Poly &C, const std::vector<byte> &Signature, uint Omega)
{
	const size_t NK = H.vec.size();
	const size_t NL = Z.vec.size();
	size_t i;
	size_t j;
	size_t k;
	size_t sigoff;
	ulong mask;
	ulong signs;

	for (i = 0; i < NL; ++i)
	{
		PolyZUnpack(Z.vec[i], Signature, i * POLZ_SIZE_PACKED);
	}
	sigoff = NL * POLZ_SIZE_PACKED;

	// dcode h
	k = 0;
	for (i = 0; i < NK; ++i)
	{
		MemoryTools::Clear(H.vec[i].coeffs, 0, N * sizeof(uint));

		if (Signature[sigoff + Omega + i] < k || Signature[sigoff + Omega + i] > Omega)
		{
			return 1;
		}

		for (j = k; j < Signature[sigoff + Omega + i]; ++j)
		{
			// coefficients are ordered for strong unforgeability
			if (j > k && Signature[sigoff + j] <= Signature[sigoff + j - 1])
			{
				return 1;
			}
			H.vec[i].coeffs[Signature[sigoff + j]] = 1;
		}

		k = Signature[sigoff + Omega + i];
	}

	// extra indices are zero for strong unforgeability
	for (j = k; j < Omega; ++j)
	{
		if (Signature[sigoff + j] != 0)
		{
			return 1;
		}
	}

	sigoff += Omega + NK;

	// decode c
	for (i = 0; i < N; ++i) // todo: not needed?
	{
		C.coeffs[i] = 0;
	}

	signs = 0;
	for (i = 0; i < 8; ++i)
	{
		signs |= static_cast<ulong>(Signature[sigoff + (N / 8) + i]) << (8 * i);
	}

	// extra sign bits are zero for strong unforgeability
	if (signs >> 60)
	{
		return 1;
	}

	mask = 1;
	for (i = 0; i < N / 8; ++i)
	{
		for (j = 0; j < 8; ++j)
		{
			if ((Signature[sigoff + i] >> j) & 0x01)
			{
				C.coeffs[(8 * i) + j] = (signs & mask) ? Q - 1 : 1;
				mask <<= 1;
			}
		}
	}

	return 0;
}

void DLMN256Q8380417::UnPackSk(std::vector<byte> &Rho, std::vector<byte> &Key, std::vector<byte> &Tr, PolyVec &S1, PolyVec &S2, PolyVec &T0, const std::vector<byte> &Sk, uint Eta, size_t EtaPack)
{
	const size_t NK = S2.vec.size();
	const size_t NL = S1.vec.size();
	size_t i;
	size_t skoff;

	MemoryTools::Copy(Sk, 0, Rho, 0, SEEDBYTES);
	skoff = SEEDBYTES;

	MemoryTools::Copy(Sk, skoff, Key, 0, SEEDBYTES);
	skoff += SEEDBYTES;

	MemoryTools::Copy(Sk, skoff, Tr, 0, CRHBYTES);
	skoff += CRHBYTES;

	for (i = 0; i < NL; ++i)
	{
		PolyEtaUnpack(S1.vec[i], Sk, skoff + (i * EtaPack), Eta);
	}
	skoff += NL * EtaPack;

	for (i = 0; i < NK; ++i)
	{
		PolyEtaUnpack(S2.vec[i], Sk, skoff + (i * EtaPack), Eta);
	}
	skoff += NK * EtaPack;

	for (i = 0; i < NK; ++i)
	{
		PolyT0Unpack(T0.vec[i], Sk, skoff + (i * POLT0_SIZE_PACKED));
	}
}

uint DLMN256Q8380417::UseHint(const uint A, const uint Hint)
{
	uint a0;
	uint a1;

	a1 = Decompose(A, a0);

	if (Hint == 0)
	{
		return a1;
	}
	else if (a0 > Q)
	{
		return (a1 + 1) & 0x0F;
	}
	else
	{
		return (a1 - 1) & 0x0F;
	}
}

void DLMN256Q8380417::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, DilithiumParameters Params)
{
	DlmParams cparams(Params);
	std::vector<byte> rho(SEEDBYTES);
	std::vector<byte> rhoprime(SEEDBYTES);
	std::vector<byte> seed(SEEDBYTES);
	std::vector<byte> tr(CRHBYTES);
	std::vector<byte> key(SEEDBYTES);
	std::vector<PolyVec> mat(cparams.K);
	PolyVec s1(cparams.L);
	PolyVec s1hat(cparams.L);
	PolyVec s2(cparams.K);
	PolyVec t(cparams.K);
	PolyVec t0(cparams.K);
	PolyVec t1(cparams.K);
	size_t i;
	ushort nonce;

	for (size_t i = 0; i < cparams.K; ++i)
	{
		mat[i] = PolyVec(cparams.L);
	}

	nonce = 0;
	// expand 32 bytes of randomness into rho, rhoprime and key
	Rng->Generate(seed);
	SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(seed);
	gen.Generate(rho);
	gen.Generate(rhoprime);
	gen.Generate(key);
	// expand matrix
	ExpandMatrix(mat, rho);

	// sample short vectors s1 and s2
	for (i = 0; i < cparams.L; ++i)
	{
		PolyUniformEta(s1.vec[i], rhoprime, nonce++, cparams.ETA);
	}
	for (i = 0; i < cparams.K; ++i)
	{
		PolyUniformEta(s2.vec[i], rhoprime, nonce++, cparams.ETA);
	}

	// matrix-vector multiplication
	s1hat = s1;
	PolyVecNtt(s1hat);

	for (i = 0; i < cparams.K; ++i)
	{
		PolyVecPointwiseAccInvMontgomery(t.vec[i], mat[i], s1hat);
		PolyReduce(t.vec[i]);
		PolyInvNttMontgomery(t.vec[i]);
	}

	// add noise vector s2
	PolyVecAdd(t, t, s2);
	// extract t1 and write public key
	PolyVecFreeze(t);
	PolyVecPower2Round(t1, t0, t);
	PackPk(PublicKey, rho, t1);
	// compute CRH(rho, t1) and write secret key
	gen.Initialize(PublicKey);
	gen.Generate(tr, 0, CRHBYTES);
	PackSk(PrivateKey, rho, key, tr, s1, s2, t0, cparams.ETA, cparams.POLETAPACK);
}

DLMN256Q8380417::DlmParams DLMN256Q8380417::GetParams(DilithiumParameters ParamType)
{
	DlmParams cparams(ParamType);

	return cparams;
}

size_t DLMN256Q8380417::Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, DilithiumParameters Params)
{
	DlmParams cparams(Params);
	const size_t MSGLEN = Message.size();
	std::vector<byte> key(SEEDBYTES);
	std::vector<byte> mu(CRHBYTES);
	std::vector<byte> rho(SEEDBYTES);
	std::vector<byte> tr(CRHBYTES);
	std::vector<byte> tmps(CRHBYTES + MSGLEN);
	std::vector<PolyVec> mat(cparams.K);
	PolyVec h(cparams.K);
	PolyVec s1(cparams.L);
	PolyVec s2(cparams.K);
	PolyVec t0(cparams.K);
	PolyVec ct0(cparams.K);
	PolyVec tmp(cparams.K);
	PolyVec w(cparams.K);
	PolyVec w1(cparams.K);
	PolyVec wcs2(cparams.K);
	PolyVec wcs20(cparams.K);
	PolyVec y(cparams.L);
	PolyVec yhat(cparams.L);
	PolyVec z(cparams.L);
	Poly c;
	Poly chat;
	ulong i;
	ulong j;
	uint n;
	ushort nonce;

	nonce = 0;
	for (size_t i = 0; i < cparams.K; ++i)
	{
		mat[i] = PolyVec(cparams.L);
	}

	UnPackSk(rho, key, tr, s1, s2, t0, PrivateKey, cparams.ETA, cparams.POLETAPACK);

	// copy tr and message into the sm buffer,
	// backwards since m and sm can be equal in SUPERCOP API
	for (i = 1; i <= MSGLEN; ++i)
	{
		Signature[cparams.SignatureSize + MSGLEN - i] = Message[MSGLEN - i];
	}

	MemoryTools::Copy(tr, 0, Signature, cparams.SignatureSize - CRHBYTES, CRHBYTES);

	// compute CRH(tr, msg)
	SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	MemoryTools::Copy(Signature, cparams.SignatureSize - CRHBYTES, tmps, 0, CRHBYTES + MSGLEN);
	gen.Initialize(tmps);
	gen.Generate(mu, 0, CRHBYTES);

	// expand matrix and transform vectors
	ExpandMatrix(mat, rho);
	PolyVecNtt(s1);
	PolyVecNtt(s2);
	PolyVecNtt(t0);

	while (true)
	{
		// sample intermediate vector y
		for (i = 0; i < cparams.L; ++i)
		{
			PolyUniformGamma1M1(y.vec[i], key, mu, nonce++);
		}

		// matrix-vector multiplication
		yhat = y;
		PolyVecNtt(yhat);

		for (i = 0; i < cparams.K; ++i)
		{
			PolyVecPointwiseAccInvMontgomery(w.vec[i], mat[i], yhat);
			PolyReduce(w.vec[i]);
			PolyInvNttMontgomery(w.vec[i]);
		}

		// decompose w and call the random oracle
		PolyVecCSubq(w);
		PolyVecDecompose(w1, tmp, w);
		Challenge(c, mu, w1);

		// compute z, reject if it reveals secret
		chat = c;
		PolyNtt(chat);

		for (i = 0; i < cparams.L; ++i)
		{
			PolyPointwiseInvMontgomery(z.vec[i], chat, s1.vec[i]);
			PolyInvNttMontgomery(z.vec[i]);
		}

		PolyVecAdd(z, z, y);
		PolyVecFreeze(z);

		if (PolyVecChkNorm(z, GAMMA1 - cparams.BETA))
		{
			continue;
		}

		// compute w - cs2, reject if w1 can not be computed from it
		for (i = 0; i < cparams.K; ++i)
		{
			PolyPointwiseInvMontgomery(wcs2.vec[i], chat, s2.vec[i]);
			PolyInvNttMontgomery(wcs2.vec[i]);
		}

		PolyVecSub(wcs2, w, wcs2);
		PolyVecFreeze(wcs2);
		PolyVecDecompose(tmp, wcs20, wcs2);
		PolyVecCSubq(wcs20);

		if (PolyVecChkNorm(wcs20, GAMMA2 - cparams.BETA))
		{
			continue;
		}

		for (i = 0; i < cparams.K; ++i)
		{
			for (j = 0; j < N; ++j)
			{
				if (tmp.vec[i].coeffs[j] != w1.vec[i].coeffs[j])
				{
					continue;
				}
			}
		}

		// compute hints for w1 PolyPointwiseInvMontgomery
		for (i = 0; i < cparams.K; ++i)
		{
			PolyPointwiseInvMontgomery(ct0.vec[i], chat, t0.vec[i]);
			PolyInvNttMontgomery(ct0.vec[i]);
		}

		PolyVecCSubq(ct0);

		if (PolyVecChkNorm(ct0, GAMMA2))
		{
			continue;
		}

		PolyVecAdd(tmp, wcs2, ct0);
		PolyVecCSubq(tmp);
		n = PolyVecMakeHint(h, wcs2, tmp);

		if (n <= cparams.OMEGA)
		{
			break;
		}
	}

	// write signature
	PackSig(Signature, z, h, c, cparams.OMEGA);

	return 0;
}

uint DLMN256Q8380417::Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, DilithiumParameters Params)
{
	DlmParams cparams(Params);
	const size_t MSGLEN = Signature.size() - cparams.SignatureSize;
	std::vector<byte> rho(SEEDBYTES);
	std::vector<byte> mu(CRHBYTES);
	std::vector<byte> tmsg(Signature.size());
	std::vector<PolyVec> mat(cparams.K);
	PolyVec z(cparams.L);
	PolyVec h(cparams.K);
	PolyVec t1(cparams.K);
	PolyVec tmp1(cparams.K);
	PolyVec tmp2(cparams.K);
	PolyVec w1(cparams.K);
	Poly c;
	Poly chat;
	Poly cp;
	size_t i;

	for (size_t i = 0; i < cparams.K; ++i)
	{
		mat[i] = PolyVec(cparams.L);
	}

	if (Signature.size() < cparams.SignatureSize)
	{
		return 0;
	}

	UnPackPk(rho, t1, PublicKey);

	if (UnPackSig(z, h, c, Signature, cparams.OMEGA))
	{
		return 0;
	}

	if (PolyVecChkNorm(z, GAMMA1 - cparams.BETA))
	{
		return 0;
	}

	// compute CRH(CRH(rho, t1), msg) using m as 'playground' buffer
	MemoryTools::Copy(Message, 0, tmsg, 0, Message.size());

	if (Signature != tmsg)
	{
		for (i = 0; i < MSGLEN; ++i)
		{
			tmsg[cparams.SignatureSize + i] = Signature[cparams.SignatureSize + i];
		}
	}

	SHAKE gen(Enumeration::ShakeModes::SHAKE256);
	gen.Initialize(PublicKey, 0, cparams.PublicKeySize);
	gen.Generate(tmsg, cparams.SignatureSize - CRHBYTES, CRHBYTES);
	gen.Initialize(tmsg, cparams.SignatureSize - CRHBYTES, CRHBYTES + MSGLEN);
	gen.Generate(mu, 0, CRHBYTES);

	// matrix-vector multiplication; compute Az - c2^dt1
	ExpandMatrix(mat, rho);
	PolyVecNtt(z);

	for (i = 0; i < cparams.K; ++i)
	{
		PolyVecPointwiseAccInvMontgomery(tmp1.vec[i], mat[i], z);
	}

	chat = c;
	PolyNtt(chat);
	PolyVecShiftL(t1, D);
	PolyVecNtt(t1);

	for (i = 0; i < cparams.K; ++i)
	{
		PolyPointwiseInvMontgomery(tmp2.vec[i], chat, t1.vec[i]);
	}

	PolyVecSub(tmp1, tmp1, tmp2);
	PolyVecReduce(tmp1);
	PolyVecInvNttMontgomery(tmp1);
	// reconstruct w1
	PolyVecCSubq(tmp1);
	PolyVecUseHint(w1, tmp1, h);
	// call random oracle and verify challenge
	Challenge(cp, mu, w1);

	for (i = 0; i < N; ++i)
	{
		if (c.coeffs[i] != cp.coeffs[i])
		{
			return 0;
		}
	}

	// all good, copy msg, return 1
	MemoryTools::Copy(Signature, cparams.SignatureSize, Message, 0, MSGLEN);

	return 1;
}

NAMESPACE_DILITHIUMEND