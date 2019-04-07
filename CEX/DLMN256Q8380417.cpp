#include "DLMN256Q8380417.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_DILITHIUM

using Utility::IntegerTools;
using Digest::Keccak;
using Utility::MemoryTools;

const std::vector<uint> DLMN256Q8380417::Zetas =
{
	0x00000000UL, 0x000064F7UL, 0x00581103UL, 0x0077F504UL, 0x00039E44UL, 0x00740119UL, 0x00728129UL, 0x00071E24UL,
	0x001BDE2BUL, 0x0023E92BUL, 0x007A64AEUL, 0x005FF480UL, 0x002F9A75UL, 0x0053DB0AUL, 0x002F7A49UL, 0x0028E527UL,
	0x00299658UL, 0x000FA070UL, 0x006F65A5UL, 0x0036B788UL, 0x00777D91UL, 0x006ECAA1UL, 0x0027F968UL, 0x005FB37CUL,
	0x005F8DD7UL, 0x0044FAE8UL, 0x006A84F8UL, 0x004DDC99UL, 0x001AD035UL, 0x007F9423UL, 0x003D3201UL, 0x000445C5UL,
	0x00294A67UL, 0x00017620UL, 0x002EF4CDUL, 0x0035DEC5UL, 0x00668504UL, 0x0049102DUL, 0x005927D5UL, 0x003BBEAFUL,
	0x0044F586UL, 0x00516E7DUL, 0x00368A96UL, 0x00541E42UL, 0x00360400UL, 0x007B4A4EUL, 0x0023D69CUL, 0x0077A55EUL,
	0x0065F23EUL, 0x0066CAD7UL, 0x00357E1EUL, 0x00458F5AUL, 0x0035843FUL, 0x005F3618UL, 0x0067745DUL, 0x0038738CUL,
	0x000C63A8UL, 0x00081B9AUL, 0x000E8F76UL, 0x003B3853UL, 0x003B8534UL, 0x0058DC31UL, 0x001F9D54UL, 0x00552F2EUL,
	0x0043E6E6UL, 0x00688C82UL, 0x0047C1D0UL, 0x0051781AUL, 0x0069B65EUL, 0x003509EEUL, 0x002135C7UL, 0x0067AFBCUL,
	0x006CAF76UL, 0x001D9772UL, 0x00419073UL, 0x00709CF7UL, 0x004F3281UL, 0x004FB2AFUL, 0x004870E1UL, 0x0001EFCAUL,
	0x003410F2UL, 0x0070DE86UL, 0x0020C638UL, 0x00296E9FUL, 0x005297A4UL, 0x0047844CUL, 0x00799A6EUL, 0x005A140AUL,
	0x0075A283UL, 0x006D2114UL, 0x007F863CUL, 0x006BE9F8UL, 0x007A0BDEUL, 0x001495D4UL, 0x001C4563UL, 0x006A0C63UL,
	0x004CDBEAUL, 0x00040AF0UL, 0x0007C417UL, 0x002F4588UL, 0x0000AD00UL, 0x006F16BFUL, 0x000DCD44UL, 0x003C675AUL,
	0x00470BCBUL, 0x007FBE7FUL, 0x00193948UL, 0x004E49C1UL, 0x0024756CUL, 0x007CA7E0UL, 0x000B98A1UL, 0x006BC809UL,
	0x0002E46CUL, 0x0049A809UL, 0x003036C2UL, 0x00639FF7UL, 0x005B1C94UL, 0x007D2AE1UL, 0x00141305UL, 0x00147792UL,
	0x00139E25UL, 0x0067B0E1UL, 0x00737945UL, 0x0069E803UL, 0x0051CEA3UL, 0x0044A79DUL, 0x00488058UL, 0x003A97D9UL,
	0x001FEA93UL, 0x0033FF5AUL, 0x002358D4UL, 0x003A41F8UL, 0x004CDF73UL, 0x00223DFBUL, 0x005A8BA0UL, 0x00498423UL,
	0x000412F5UL, 0x00252587UL, 0x006D04F1UL, 0x00359B5DUL, 0x004A28A1UL, 0x004682FDUL, 0x006D9B57UL, 0x004F25DFUL,
	0x000DBE5EUL, 0x001C5E1AUL, 0x000DE0E6UL, 0x000C7F5AUL, 0x00078F83UL, 0x0067428BUL, 0x007F3705UL, 0x0077E6FDUL,
	0x0075E022UL, 0x00503AF7UL, 0x001F0084UL, 0x0030EF86UL, 0x0049997EUL, 0x0077DCD7UL, 0x00742593UL, 0x004901C3UL,
	0x00053919UL, 0x0004610CUL, 0x005AAD42UL, 0x003EB01BUL, 0x003472E7UL, 0x004CE03CUL, 0x001A7CC7UL, 0x00031924UL,
	0x002B5EE5UL, 0x00291199UL, 0x00585A3BUL, 0x00134D71UL, 0x003DE11CUL, 0x00130984UL, 0x0025F051UL, 0x00185A46UL,
	0x00466519UL, 0x001314BEUL, 0x00283891UL, 0x0049BB91UL, 0x0052308AUL, 0x001C853FUL, 0x001D0B4BUL, 0x006FD6A7UL,
	0x006B88BFUL, 0x0012E11BUL, 0x004D3E3FUL, 0x006A0D30UL, 0x0078FDE5UL, 0x001406C7UL, 0x00327283UL, 0x0061ED6FUL,
	0x006C5954UL, 0x001D4099UL, 0x00590579UL, 0x006AE5AEUL, 0x0016E405UL, 0x000BDBE7UL, 0x00221DE8UL, 0x0033F8CFUL,
	0x00779935UL, 0x0054AA0DUL, 0x00665FF9UL, 0x0063B158UL, 0x0058711CUL, 0x00470C13UL, 0x000910D8UL, 0x00463E20UL,
	0x00612659UL, 0x00251D8BUL, 0x002573B7UL, 0x007D5C90UL, 0x001DDD98UL, 0x00336898UL, 0x0002D4BBUL, 0x006D73A8UL,
	0x004F4CBFUL, 0x00027C1CUL, 0x0018AA08UL, 0x002DFD71UL, 0x000C5CA5UL, 0x0019379AUL, 0x00478168UL, 0x00646C3EUL,
	0x0051813DUL, 0x0035C539UL, 0x003B0115UL, 0x00041DC0UL, 0x0021C4F7UL, 0x0070FBF5UL, 0x001A35E7UL, 0x0007340EUL,
	0x00795D46UL, 0x001A4CD0UL, 0x00645CAFUL, 0x001D2668UL, 0x00666E99UL, 0x006F0634UL, 0x007BE5DBUL, 0x00455FDCUL,
	0x00530765UL, 0x005DC1B0UL, 0x007973DEUL, 0x005CFD0AUL, 0x0002CC93UL, 0x0070F806UL, 0x00189C2AUL, 0x0049C5AAUL,
	0x00776A51UL, 0x003BCF2CUL, 0x007F234FUL, 0x006B16E0UL, 0x003C15CAUL, 0x00155E68UL, 0x0072F6B7UL, 0x001E29CEUL
};

const std::vector<uint> DLMN256Q8380417::ZetasInv =
{
	0x0061B633UL, 0x000CE94AUL, 0x006A8199UL, 0x0043CA37UL, 0x0014C921UL, 0x0000BCB2UL, 0x004410D5UL, 0x000875B0UL,
	0x00361A57UL, 0x006743D7UL, 0x000EE7FBUL, 0x007D136EUL, 0x0022E2F7UL, 0x00066C23UL, 0x00221E51UL, 0x002CD89CUL,
	0x003A8025UL, 0x0003FA26UL, 0x0010D9CDUL, 0x00197168UL, 0x0062B999UL, 0x001B8352UL, 0x00659331UL, 0x000682BBUL,
	0x0078ABF3UL, 0x0065AA1AUL, 0x000EE40CUL, 0x005E1B0AUL, 0x007BC241UL, 0x0044DEECUL, 0x004A1AC8UL, 0x002E5EC4UL,
	0x001B73C3UL, 0x00385E99UL, 0x0066A867UL, 0x0073835CUL, 0x0051E290UL, 0x006735F9UL, 0x007D63E5UL, 0x00309342UL,
	0x00126C59UL, 0x007D0B46UL, 0x004C7769UL, 0x00620269UL, 0x00028371UL, 0x005A6C4AUL, 0x005AC276UL, 0x001EB9A8UL,
	0x0039A1E1UL, 0x0076CF29UL, 0x0038D3EEUL, 0x00276EE5UL, 0x001C2EA9UL, 0x00198008UL, 0x002B35F4UL, 0x000846CCUL,
	0x004BE732UL, 0x005DC219UL, 0x0074041AUL, 0x0068FBFCUL, 0x0014FA53UL, 0x0026DA88UL, 0x00629F68UL, 0x001386ADUL,
	0x001DF292UL, 0x004D6D7EUL, 0x006BD93AUL, 0x0006E21CUL, 0x0015D2D1UL, 0x0032A1C2UL, 0x006CFEE6UL, 0x00145742UL,
	0x0010095AUL, 0x0062D4B6UL, 0x00635AC2UL, 0x002DAF77UL, 0x00362470UL, 0x0057A770UL, 0x006CCB43UL, 0x00397AE8UL,
	0x006785BBUL, 0x0059EFB0UL, 0x006CD67DUL, 0x0041FEE5UL, 0x006C9290UL, 0x002785C6UL, 0x0056CE68UL, 0x0054811CUL,
	0x007CC6DDUL, 0x0065633AUL, 0x0032FFC5UL, 0x004B6D1AUL, 0x00412FE6UL, 0x002532BFUL, 0x007B7EF5UL, 0x007AA6E8UL,
	0x0036DE3EUL, 0x000BBA6EUL, 0x0008032AUL, 0x00364683UL, 0x004EF07BUL, 0x0060DF7DUL, 0x002FA50AUL, 0x0009FFDFUL,
	0x0007F904UL, 0x0000A8FCUL, 0x00189D76UL, 0x0078507EUL, 0x007360A7UL, 0x0071FF1BUL, 0x006381E7UL, 0x007221A3UL,
	0x0030BA22UL, 0x001244AAUL, 0x00395D04UL, 0x0035B760UL, 0x004A44A4UL, 0x0012DB10UL, 0x005ABA7AUL, 0x007BCD0CUL,
	0x00365BDEUL, 0x00255461UL, 0x005DA206UL, 0x0033008EUL, 0x00459E09UL, 0x005C872DUL, 0x004BE0A7UL, 0x005FF56EUL,
	0x00454828UL, 0x00375FA9UL, 0x003B3864UL, 0x002E115EUL, 0x0015F7FEUL, 0x000C66BCUL, 0x00182F20UL, 0x006C41DCUL,
	0x006B686FUL, 0x006BCCFCUL, 0x0002B520UL, 0x0024C36DUL, 0x001C400AUL, 0x004FA93FUL, 0x003637F8UL, 0x007CFB95UL,
	0x001417F8UL, 0x00744760UL, 0x00033821UL, 0x005B6A95UL, 0x00319640UL, 0x0066A6B9UL, 0x00002182UL, 0x0038D436UL,
	0x004378A7UL, 0x007212BDUL, 0x0010C942UL, 0x007F3301UL, 0x00509A79UL, 0x00781BEAUL, 0x007BD511UL, 0x00330417UL,
	0x0015D39EUL, 0x00639A9EUL, 0x006B4A2DUL, 0x0005D423UL, 0x0013F609UL, 0x000059C5UL, 0x0012BEEDUL, 0x000A3D7EUL,
	0x0025CBF7UL, 0x00064593UL, 0x00385BB5UL, 0x002D485DUL, 0x00567162UL, 0x005F19C9UL, 0x000F017BUL, 0x004BCF0FUL,
	0x007DF037UL, 0x00376F20UL, 0x00302D52UL, 0x0030AD80UL, 0x000F430AUL, 0x003E4F8EUL, 0x0062488FUL, 0x0013308BUL,
	0x00183045UL, 0x005EAA3AUL, 0x004AD613UL, 0x001629A3UL, 0x002E67E7UL, 0x00381E31UL, 0x0017537FUL, 0x003BF91BUL,
	0x002AB0D3UL, 0x006042ADUL, 0x002703D0UL, 0x00445ACDUL, 0x0044A7AEUL, 0x0071508BUL, 0x0077C467UL, 0x00737C59UL,
	0x00476C75UL, 0x00186BA4UL, 0x0020A9E9UL, 0x004A5BC2UL, 0x003A50A7UL, 0x004A61E3UL, 0x0019152AUL, 0x0019EDC3UL,
	0x00083AA3UL, 0x005C0965UL, 0x000495B3UL, 0x0049DC01UL, 0x002BC1BFUL, 0x0049556BUL, 0x002E7184UL, 0x003AEA7BUL,
	0x00442152UL, 0x0026B82CUL, 0x0036CFD4UL, 0x00195AFDUL, 0x004A013CUL, 0x0050EB34UL, 0x007E69E1UL, 0x0056959AUL,
	0x007B9A3CUL, 0x0042AE00UL, 0x00004BDEUL, 0x00650FCCUL, 0x00320368UL, 0x00155B09UL, 0x003AE519UL, 0x0020522AUL,
	0x00202C85UL, 0x0057E699UL, 0x00111560UL, 0x00086270UL, 0x00492879UL, 0x00107A5CUL, 0x00703F91UL, 0x005649A9UL,
	0x0056FADAUL, 0x005065B8UL, 0x002C04F7UL, 0x0050458CUL, 0x001FEB81UL, 0x00057B53UL, 0x005BF6D6UL, 0x006401D6UL,
	0x0078C1DDUL, 0x000D5ED8UL, 0x000BDEE8UL, 0x007C41BDUL, 0x0007EAFDUL, 0x0027CEFEUL, 0x007F7B0AUL, 0x00000000UL
};

void DLMN256Q8380417::Challenge(Poly &C, const std::vector<byte> &Mu, const PolyVec &W1)
{
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state;
	std::vector<byte> buffer(Keccak::KECCAK256_RATE_SIZE);
	std::vector<byte> tmps(DLM_CHR_SIZE + W1.vec.size() * DLM_POLW1_PACKED);
	ulong mask;
	ulong signs;
	size_t i;
	size_t j;
	size_t k;

	MemoryTools::Copy(Mu, 0, tmps, 0, DLM_CHR_SIZE);
	
	for (i = 0; i < W1.vec.size(); ++i)
	{
		PolyW1Pack(tmps, DLM_CHR_SIZE + (i * DLM_POLW1_PACKED), W1.vec[i]);
	}

	MemoryTools::Clear(state, 0, state.size() * sizeof(ulong));
	Absorb(tmps, state);
	Squeeze(state, buffer, 1);
	signs = 0;

	for (i = 0; i < 8; ++i)
	{
		signs |= static_cast<ulong>(buffer[i]) << (8 * i);
	}

	j = 8;
	mask = 1;
	MemoryTools::Clear(C.coeffs, 0, C.coeffs.size() * sizeof(uint));

	for (i = 196; i < DLM_N; ++i)
	{
		do
		{
			if (j >= Keccak::KECCAK256_RATE_SIZE)
			{
				Squeeze(state, buffer, 1);
				j = 0;
			}

			k = static_cast<size_t>(buffer[j]);
			++j;
		} 
		while (k > i);

		C.coeffs[i] = C.coeffs[k];
		C.coeffs[k] = (signs & mask) ? DLM_Q - 1 : 1;
		mask <<= 1;
	}
}

uint DLMN256Q8380417::CSubQ(uint A)
{
	A -= DLM_Q;
	A += (static_cast<int32_t>(A) >> 31) & DLM_Q;

	return A;
}

uint DLMN256Q8380417::Decompose(uint A, uint &A0)
{
	int32_t t;
	int32_t u;

	// centralized remainder mod DLM_ALPHA
	t = A & 0x0007FFFFUL;
	t += (A >> 19) << 9;
	t -= (DLM_ALPHA / 2) + 1;
	t += (t >> 31) & DLM_ALPHA;
	t -= (DLM_ALPHA / 2) - 1;
	A -= t;
	// divide by DLM_ALPHA (possible to avoid)
	u = A - 1;
	u >>= 31;
	A = (A >> 19) + 1;
	A -= u & 1;
	// border case
	A0 = (DLM_Q + t) - (A >> 4);
	A &= 0x0000000FUL;

	return A;
}

void DLMN256Q8380417::ExpandMatrix(std::vector<PolyVec> &Mat, const std::vector<byte> &Rho)
{
	// don't change this to smaller values,
	// sampling later assumes sufficient SHAKE output!
	// probability that we need more than 5 blocks: < 2^{-132}
	// probability that we need more than 6 blocks: < 2^{-546}

	std::vector<byte> buffer(Keccak::KECCAK128_RATE_SIZE * 5);
	std::vector<byte> seed(DLM_SEED_SIZE + 1);
	size_t i;
	size_t j;

	MemoryTools::Copy(Rho, 0, seed, 0, DLM_SEED_SIZE);

	for (i = 0; i < Mat.size(); ++i)
	{
		for (j = 0; j < Mat[0].vec.size(); ++j)
		{
			seed[DLM_SEED_SIZE] = static_cast<byte>(i + (j << 4));
			XOF(seed, 0, seed.size(), buffer, 0, buffer.size(), Keccak::KECCAK128_RATE_SIZE);
			PolyUniform(Mat[i].vec[j], buffer);
		}
	}
}

uint DLMN256Q8380417::Freeze(uint A)
{
	A = Reduce32(A);
	A = CSubQ(A);

	return A;
}

void DLMN256Q8380417::InvNttFromInvMont(std::array<uint, DLM_N> &P)
{
	const ulong F = (((static_cast<ulong>(DLM_MONT) * DLM_MONT % DLM_Q) * (DLM_Q - 1) % DLM_Q) * ((DLM_Q - 1) >> 8) % DLM_Q);
	size_t j;
	size_t k;
	size_t len;
	size_t start;
	uint t;
	uint zeta;

	j = 0;
	k = 0;

	for (len = 1; len < DLM_N; len <<= 1)
	{
		for (start = 0; start < DLM_N; start = j + len)
		{
			zeta = ZetasInv[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = P[j];
				P[j] = t + P[j + len];
				P[j + len] = t + 256 * DLM_Q - P[j + len];
				P[j + len] = MontgomeryReduce(static_cast<ulong>(zeta) * P[j + len]);
			}
		}
	}

	for (j = 0; j < DLM_N; ++j)
	{
		P[j] = MontgomeryReduce(F * P[j]);
	}
}

uint DLMN256Q8380417::MakeHint(uint A, uint B)
{
	uint t;

	return Decompose(A, t) != Decompose(B, t);
}

uint DLMN256Q8380417::MontgomeryReduce(ulong A)
{
	ulong t;

	t = A * DLM_QINV;
	t &= (1ULL << 32) - 1;
	t *= DLM_Q;
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
		for (start = 0; start < DLM_N; start = j + len)
		{
			zeta = Zetas[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = MontgomeryReduce(static_cast<ulong>(zeta) * P.coeffs[j + len]);
				P.coeffs[j + len] = P.coeffs[j] + (2 * DLM_Q) - t;
				P.coeffs[j] = P.coeffs[j] + t;
			}
		}
	}
}

void DLMN256Q8380417::PackPk(std::vector<byte> &Pk, const std::vector<byte> Rho, const PolyVec &T1)
{
	size_t i;

	MemoryTools::Copy(Rho, 0, Pk, 0, DLM_SEED_SIZE);

	for (i = 0; i < T1.vec.size(); ++i)
	{
		PolyT1Pack(Pk, DLM_SEED_SIZE + (i * DLM_POLT1_PACKED), T1.vec[i]);
	}
}

void DLMN256Q8380417::PackSig(std::vector<byte> &Signature, const PolyVec &Z, const PolyVec &H, const Poly &C, uint Omega)
{
	ulong mask;
	ulong signs;
	size_t i;
	size_t j;
	size_t k;
	size_t ofts;

	for (i = 0; i < Z.vec.size(); ++i)
	{
		PolyZPack(Signature, i * DLM_POLZ_PACKED, Z.vec[i]);
	}

	ofts = Z.vec.size() * DLM_POLZ_PACKED;
	k = 0;

	// encode h
	for (i = 0; i < H.vec.size(); ++i)
	{
		for (j = 0; j < DLM_N; ++j)
		{
			if (H.vec[i].coeffs[j] != 0)
			{
				Signature[ofts + k] = static_cast<byte>(j);
				++k;
			}
		}

		Signature[ofts + Omega + i] = static_cast<byte>(k);
	}

	while (k < Omega)
	{
		Signature[ofts + k] = 0;
		++k;
	}

	ofts += Omega + H.vec.size();
	signs = 0;
	mask = 1;

	// encode c
	for (i = 0; i < DLM_N / 8; ++i)
	{
		Signature[ofts + i] = 0;

		for (j = 0; j < 8; ++j)
		{
			if (C.coeffs[8 * i + j] != 0)
			{
				Signature[ofts + i] |= (1U << j);

				if (C.coeffs[8 * i + j] == (DLM_Q - 1))
				{
					signs |= mask;
				}

				mask <<= 1;
			}
		}
	}

	ofts += DLM_N / 8;

	for (i = 0; i < 8; ++i)
	{
		Signature[ofts + i] = signs >> 8 * i;
	}
}

void DLMN256Q8380417::PackSk(std::vector<byte> &Sk, const std::vector<byte> &Rho, const std::vector<byte> &Key, const std::vector<byte> &Tr, const PolyVec &S1, const PolyVec &S2, const PolyVec &T0, uint Eta, size_t EtaPack)
{
	size_t i;
	size_t skoft;

	MemoryTools::Copy(Rho, 0, Sk, 0, DLM_SEED_SIZE);
	skoft = DLM_SEED_SIZE;
	MemoryTools::Copy(Key, 0, Sk, skoft, DLM_SEED_SIZE);
	skoft += DLM_SEED_SIZE;
	MemoryTools::Copy(Tr, 0, Sk, skoft, DLM_CHR_SIZE);
	skoft += DLM_CHR_SIZE;

	for (i = 0; i < S1.vec.size(); ++i)
	{
		PolyEtaPack(Sk, skoft + (i * EtaPack), S1.vec[i], Eta);
	}

	skoft += S1.vec.size() * EtaPack;

	for (i = 0; i < S2.vec.size(); ++i)
	{
		PolyEtaPack(Sk, skoft + (i * EtaPack), S2.vec[i], Eta);
	}

	skoft += S2.vec.size() * EtaPack;

	for (i = 0; i < S2.vec.size(); ++i)
	{
		PolyT0Pack(Sk, skoft + (i * DLM_POLT0_PACKED), T0.vec[i]);
	}
}

void DLMN256Q8380417::PolyAdd(Poly &C, const Poly &A, const Poly &B)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
	{
		C.coeffs[i] = A.coeffs[i] + B.coeffs[i];
	}
}

int32_t DLMN256Q8380417::PolyChkNorm(const Poly &A, uint B)
{
	size_t i;
	int32_t ret;
	int32_t t;

	ret = 0;

	// it is ok to leak which coefficient violates the bound since
	// the probability for each coefficient is independent of secret
	// data but we must not leak the sign of the centralized representative
	for (i = 0; i < DLM_N; ++i)
	{
		// absolute value of centralized representative
		t = ((DLM_Q - 1) / 2) - A.coeffs[i];
		t ^= (t >> 31);
		t = ((DLM_Q - 1) / 2) - t;

		if (static_cast<uint>(t) >= B)
		{
			ret = 1;
			break;
		}
	}

	return ret;
}

void DLMN256Q8380417::PolyCSubq(Poly &A)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
	{
		A.coeffs[i] = CSubQ(A.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyDecompose(Poly &A1, Poly &A0, const Poly &A)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
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
		for (i = 0; i < DLM_N / 8; ++i)
		{
			t[0] = DLM_Q + Eta - A.coeffs[(8 * i)];
			t[1] = DLM_Q + Eta - A.coeffs[(8 * i) + 1];
			t[2] = DLM_Q + Eta - A.coeffs[(8 * i) + 2];
			t[3] = DLM_Q + Eta - A.coeffs[(8 * i) + 3];
			t[4] = DLM_Q + Eta - A.coeffs[(8 * i) + 4];
			t[5] = DLM_Q + Eta - A.coeffs[(8 * i) + 5];
			t[6] = DLM_Q + Eta - A.coeffs[(8 * i) + 6];
			t[7] = DLM_Q + Eta - A.coeffs[(8 * i) + 7];

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
		for (i = 0; i < DLM_N / 2; ++i)
		{
			t[0] = DLM_Q + Eta - A.coeffs[(2 * i)];
			t[1] = DLM_Q + Eta - A.coeffs[(2 * i) + 1];
			R[ROffset + i] = t[0] | (t[1] << 4);
		}
	}
}

void DLMN256Q8380417::PolyEtaUnpack(Poly &R, const std::vector<byte> &A, size_t AOffset, uint Eta)
{
	size_t i;

	if (Eta <= 3) 
	{
		for (i = 0; i < DLM_N / 8; ++i)
		{
			R.coeffs[(8 * i)] = A[(3 * i) + AOffset] & 0x07;
			R.coeffs[(8 * i) + 1] = (A[(3 * i) + AOffset] >> 3) & 0x07;
			R.coeffs[(8 * i) + 2] = (A[(3 * i) + AOffset] >> 6) | ((A[(3 * i) + AOffset + 1] & 0x01) << 2);
			R.coeffs[(8 * i) + 3] = (A[(3 * i) + AOffset + 1] >> 1) & 0x07;
			R.coeffs[(8 * i) + 4] = (A[(3 * i) + AOffset + 1] >> 4) & 0x07;
			R.coeffs[(8 * i) + 5] = (A[(3 * i) + AOffset + 1] >> 7) | ((A[(3 * i) + AOffset + 2] & 0x03) << 1);
			R.coeffs[(8 * i) + 6] = (A[(3 * i) + AOffset + 2] >> 2) & 0x07;
			R.coeffs[(8 * i) + 7] = (A[(3 * i) + AOffset + 2] >> 5);

			R.coeffs[(8 * i)] = DLM_Q + Eta - R.coeffs[(8 * i)];
			R.coeffs[(8 * i) + 1] = DLM_Q + Eta - R.coeffs[(8 * i) + 1];
			R.coeffs[(8 * i) + 2] = DLM_Q + Eta - R.coeffs[(8 * i) + 2];
			R.coeffs[(8 * i) + 3] = DLM_Q + Eta - R.coeffs[(8 * i) + 3];
			R.coeffs[(8 * i) + 4] = DLM_Q + Eta - R.coeffs[(8 * i) + 4];
			R.coeffs[(8 * i) + 5] = DLM_Q + Eta - R.coeffs[(8 * i) + 5];
			R.coeffs[(8 * i) + 6] = DLM_Q + Eta - R.coeffs[(8 * i) + 6];
			R.coeffs[(8 * i) + 7] = DLM_Q + Eta - R.coeffs[(8 * i) + 7];
		}
	}
	else
	{
		for (i = 0; i < DLM_N / 2; ++i)
		{
			R.coeffs[(2 * i)] = A[AOffset + i] & 0x0F;
			R.coeffs[(2 * i) + 1] = A[AOffset + i] >> 4;
			R.coeffs[(2 * i)] = DLM_Q + Eta - R.coeffs[(2 * i)];
			R.coeffs[(2 * i) + 1] = DLM_Q + Eta - R.coeffs[(2 * i) + 1];
		}
	}
}

void DLMN256Q8380417::PolyFreeze(Poly &A)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
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

	for (i = 0; i < DLM_N; ++i)
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

	for (i = 0; i < DLM_N; ++i)
	{
		C.coeffs[i] = MontgomeryReduce(static_cast<ulong>(A.coeffs[i]) * B.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyPower2Round(Poly &A1, Poly &A0, const Poly &A)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
	{
		A1.coeffs[i] = Power2Round(A.coeffs[i], A0.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyReduce(Poly &A)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
	{
		A.coeffs[i] = Reduce32(A.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyShiftL(Poly &A, uint Shift)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
	{
		A.coeffs[i] <<= Shift;
	}
}

void DLMN256Q8380417::PolySub(Poly &C, const Poly &A, const Poly &B)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
	{
		C.coeffs[i] = A.coeffs[i] + (2 * DLM_Q) - B.coeffs[i];
	}
}

void DLMN256Q8380417::PolyT0Pack(std::vector<byte> &R, size_t ROffset, const Poly &A)
{
	std::array<uint, 4> t;
	size_t i;

	for (i = 0; i < DLM_N / 4; ++i)
	{
		t[0] = DLM_Q + (1 << (DLM_D - 1)) - A.coeffs[(4 * i)];
		t[1] = DLM_Q + (1 << (DLM_D - 1)) - A.coeffs[(4 * i) + 1];
		t[2] = DLM_Q + (1 << (DLM_D - 1)) - A.coeffs[(4 * i) + 2];
		t[3] = DLM_Q + (1 << (DLM_D - 1)) - A.coeffs[(4 * i) + 3];

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

	for (i = 0; i < DLM_N / 4; ++i)
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
		R.coeffs[(4 * i)] = DLM_Q + (1 << (DLM_D - 1)) - R.coeffs[(4 * i)];
		R.coeffs[(4 * i) + 1] = DLM_Q + (1 << (DLM_D - 1)) - R.coeffs[(4 * i) + 1];
		R.coeffs[(4 * i) + 2] = DLM_Q + (1 << (DLM_D - 1)) - R.coeffs[(4 * i) + 2];
		R.coeffs[(4 * i) + 3] = DLM_Q + (1 << (DLM_D - 1)) - R.coeffs[(4 * i) + 3];
	}
}

void DLMN256Q8380417::PolyT1Pack(std::vector<byte> &R, size_t ROffset, const Poly &A)
{
	size_t i;

	for (i = 0; i < DLM_N / 8; ++i)
	{
		R[(9 * i) + ROffset] = A.coeffs[(8 * i)] & 0xFF;
		R[(9 * i) + ROffset + 1] = (A.coeffs[(8 * i)] >> 8) | ((A.coeffs[(8 * i) + 1] & 0x7F) << 1);
		R[(9 * i) + ROffset + 2] = (A.coeffs[(8 * i) + 1] >> 7) | ((A.coeffs[(8 * i) + 2] & 0x3F) << 2);
		R[(9 * i) + ROffset + 3] = (A.coeffs[(8 * i) + 2] >> 6) | ((A.coeffs[(8 * i) + 3] & 0x1F) << 3);
		R[(9 * i) + ROffset + 4] = (A.coeffs[(8 * i) + 3] >> 5) | ((A.coeffs[(8 * i) + 4] & 0x0F) << 4);
		R[(9 * i) + ROffset + 5] = (A.coeffs[(8 * i) + 4] >> 4) | ((A.coeffs[(8 * i) + 5] & 0x07) << 5);
		R[(9 * i) + ROffset + 6] = (A.coeffs[(8 * i) + 5] >> 3) | ((A.coeffs[(8 * i) + 6] & 0x03) << 6);
		R[(9 * i) + ROffset + 7] = (A.coeffs[(8 * i) + 6] >> 2) | ((A.coeffs[(8 * i) + 7] & 0x01) << 7);
		R[(9 * i) + ROffset + 8] = (A.coeffs[(8 * i) + 7] >> 1);
	}
}

void DLMN256Q8380417::PolyT1Unpack(Poly &R, const std::vector<byte> &A, size_t AOffset)
{
	size_t i;

	for (i = 0; i < DLM_N / 8; ++i)
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

	while (ctr < DLM_N)
	{
		t = Input[pos];
		++pos;
		t |= static_cast<uint>(Input[pos]) << 8;
		++pos;
		t |= static_cast<uint>(Input[pos]) << 16;
		++pos;
		t &= 0x007FFFFFUL;

		if (t < DLM_Q)
		{
			A.coeffs[ctr] = t;
			++ctr;
		}
	}
}

void DLMN256Q8380417::PolyUniformEta(Poly &A, const std::vector<byte> &Seed, byte Nonce, uint Eta)
{
	// probability that we need more than 2 blocks: < 2^{-84}, 3 blocks: < 2^{-352}
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state;
	std::vector<byte> tmps(DLM_SEED_SIZE + 1);
	std::vector<byte> buffer(Keccak::KECCAK256_RATE_SIZE * 2);
	uint ctr;

	MemoryTools::Copy(Seed, 0, tmps, 0, DLM_SEED_SIZE);
	tmps[DLM_SEED_SIZE] = Nonce;

	MemoryTools::Clear(state, 0, state.size() * sizeof(ulong));
	Absorb(tmps, state);
	Squeeze(state, buffer, 2);

	ctr = RejEta(A.coeffs, 0, DLM_N, buffer, buffer.size(), Eta);

	if (ctr < DLM_N)
	{
		Squeeze(state, buffer, 1);
		RejEta(A.coeffs, ctr, DLM_N - ctr, buffer, Keccak::KECCAK256_RATE_SIZE, Eta);
	}
}

void DLMN256Q8380417::PolyUniformGamma1M1(Poly &A, const std::vector<byte> &Seed, const std::vector<byte> &Mu, ushort Nonce)
{
	// probability that we need more than 5 blocks: < 2^{-81}
	// probability that we need more than 6 blocks: < 2^{-467}

	std::vector<byte> buffer(Keccak::KECCAK256_RATE_SIZE * 5);
	std::vector<byte> tmps(DLM_SEED_SIZE + DLM_CHR_SIZE + 2);
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state;
	uint ctr;

	MemoryTools::Copy(Seed, 0, tmps, 0, DLM_SEED_SIZE);
	MemoryTools::Copy(Mu, 0, tmps, DLM_SEED_SIZE, DLM_CHR_SIZE);
	tmps[DLM_SEED_SIZE + DLM_CHR_SIZE] = Nonce & 0xFF;
	tmps[DLM_SEED_SIZE + DLM_CHR_SIZE + 1] = Nonce >> 8;

	MemoryTools::Clear(state, 0, state.size() * sizeof(ulong));
	Absorb(tmps, state);
	Squeeze(state, buffer, 5);

	ctr = RejGamma1M1(A.coeffs, 0, DLM_N, buffer, buffer.size());

	if (ctr < DLM_N)
	{
		// there are no bytes left in outbuf since 5 * KECCAK256_RATE_SIZE is divisible by 5
		Squeeze(state, buffer, 1);
		RejGamma1M1(A.coeffs, ctr, DLM_N - ctr, buffer, Keccak::KECCAK256_RATE_SIZE);
	}
}

void DLMN256Q8380417::PolyUseHint(Poly &A, const Poly &B, const Poly &H)
{
	size_t i;

	for (i = 0; i < DLM_N; ++i)
	{
		A.coeffs[i] = UseHint(B.coeffs[i], H.coeffs[i]);
	}
}

void DLMN256Q8380417::PolyW1Pack(std::vector<byte> &R, size_t ROffset, const Poly &A)
{
	size_t i;

	for (i = 0; i < DLM_N / 2; ++i)
	{
		R[ROffset + i] = A.coeffs[(2 * i)] | (A.coeffs[(2 * i) + 1] << 4);
	}
}

void DLMN256Q8380417::PolyZPack(std::vector<byte> &R, size_t ROffset, const Poly &A)
{
	std::array<uint, 2> t;
	size_t i;

	for (i = 0; i < DLM_N / 2; ++i)
	{
		// map to {0,...,2*DLM_GAMMA1 - 2}
		t[0] = DLM_GAMMA1 - 1 - A.coeffs[(2 * i)];
		t[0] += (static_cast<int32_t>(t[0]) >> 31) & DLM_Q;
		t[1] = DLM_GAMMA1 - 1 - A.coeffs[(2 * i) + 1];
		t[1] += (static_cast<int32_t>(t[1]) >> 31) & DLM_Q;

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

	for (i = 0; i < DLM_N / 2; ++i)
	{
		R.coeffs[(2 * i)] = A[(5 * i) + AOffset];
		R.coeffs[(2 * i)] |= static_cast<uint>(A[(5 * i) + AOffset + 1]) << 8;
		R.coeffs[(2 * i)] |= static_cast<uint>(A[(5 * i) + AOffset + 2] & 0x0F) << 16;
		R.coeffs[(2 * i) + 1] = A[(5 * i) + AOffset + 2] >> 4;
		R.coeffs[(2 * i) + 1] |= static_cast<uint>(A[(5 * i) + AOffset + 3]) << 4;
		R.coeffs[(2 * i) + 1] |= static_cast<uint>(A[(5 * i) + AOffset + 4]) << 12;
		R.coeffs[(2 * i)] = DLM_GAMMA1 - 1 - R.coeffs[(2 * i)];
		R.coeffs[(2 * i)] += (static_cast<int32_t>(R.coeffs[(2 * i)]) >> 31) & DLM_Q;
		R.coeffs[(2 * i) + 1] = DLM_GAMMA1 - 1 - R.coeffs[(2 * i) + 1];
		R.coeffs[(2 * i) + 1] += (static_cast<int32_t>(R.coeffs[(2 * i) + 1]) >> 31) & DLM_Q;
	}
}

uint DLMN256Q8380417::Power2Round(uint A, uint &A0)
{
	int32_t t;

	// centralized remainder mod 2^DLM_D
	t = A & ((1 << DLM_D) - 1);
	t -= (1 << (DLM_D - 1)) + 1;
	t += (t >> 31) & (1 << DLM_D);
	t -= (1 << (DLM_D - 1)) - 1;
	A0 = DLM_Q + t;
	A = (A - t) >> DLM_D;

	return A;
}

uint DLMN256Q8380417::Reduce32(uint A)
{
	uint t;

	t = A & 0x007FFFFFUL;
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
			A[AOffset + ctr] = DLM_Q + Eta - t0;
			++ctr;
		}

		if (t1 <= 2 * Eta && ctr < ALength)
		{
			A[AOffset + ctr] = DLM_Q + Eta - t1;
			++ctr;
		}
	}

	return ctr;
}

uint DLMN256Q8380417::RejGamma1M1(std::array<uint, 256> &A, size_t Offset, size_t ALength, const std::vector<byte> &Buffer, size_t BufLength)
{
	size_t pos;
	uint ctr;
	uint t0;
	uint t1;

	ctr = 0;
	pos = 0;

	while (ctr < ALength && pos + 5 <= BufLength)
	{
		t0 = Buffer[pos];
		t0 |= static_cast<uint>(Buffer[pos + 1]) << 8;
		t0 |= static_cast<uint>(Buffer[pos + 2]) << 16;
		t0 &= 0x000FFFFFUL;

		t1 = Buffer[pos + 2] >> 4;
		t1 |= static_cast<uint>(Buffer[pos + 3]) << 4;
		t1 |= static_cast<uint>(Buffer[pos + 4]) << 12;
		pos += 5;

		if (t0 <= (2 * DLM_GAMMA1) - 2)
		{
			A[Offset + ctr] = DLM_Q + DLM_GAMMA1 - 1 - t0;
			++ctr;
		}

		if (t1 <= (2 * DLM_GAMMA1) - 2 && ctr < ALength)
		{
			A[Offset + ctr] = DLM_Q + DLM_GAMMA1 - 1 - t1;
			++ctr;
		}
	}

	return ctr;
}

void DLMN256Q8380417::UnPackPk(std::vector<byte> &Rho, PolyVec &T1, const std::vector<byte> &Pk)
{
	size_t i;

	MemoryTools::Copy(Pk, 0, Rho, 0, DLM_SEED_SIZE);

	for (i = 0; i < T1.vec.size(); ++i)
	{
		PolyT1Unpack(T1.vec[i], Pk, DLM_SEED_SIZE + (i * DLM_POLT1_PACKED));
	}
}

bool DLMN256Q8380417::UnPackSig(PolyVec &Z, PolyVec &H, Poly &C, const std::vector<byte> &Signature, uint Omega)
{
	bool ret;
	size_t i;
	size_t j;
	size_t k;
	size_t ofts;
	ulong mask;
	ulong signs;

	for (i = 0; i < Z.vec.size(); ++i)
	{
		PolyZUnpack(Z.vec[i], Signature, i * DLM_POLZ_PACKED);
	}

	ofts = Z.vec.size() * DLM_POLZ_PACKED;
	k = 0;
	ret = true;

	// decode h
	for (i = 0; i < H.vec.size(); ++i)
	{
		MemoryTools::Clear(H.vec[i].coeffs, 0, DLM_N * sizeof(uint));

		if (Signature[ofts + Omega + i] < k || Signature[ofts + Omega + i] > Omega)
		{
			ret = false;
			break;
		}

		for (j = k; j < Signature[ofts + Omega + i]; ++j)
		{
			// coefficients are ordered for strong unforgeability
			if (j > k && Signature[ofts + j] <= Signature[ofts + j - 1])
			{
				ret = false;
				break;
			}

			H.vec[i].coeffs[Signature[ofts + j]] = 1;
		}

		if (ret == false)
		{
			break;
		}

		k = Signature[ofts + Omega + i];
	}

	// extra indices are zero for strong unforgeability
	if (ret == true)
	{
		for (j = k; j < Omega; ++j)
		{
			if (Signature[ofts + j] != 0)
			{
				ret = false;
				break;
			}
		}
	}

	if (ret == true)
	{
		ofts += Omega + H.vec.size();

		// decode c
		MemoryTools::Clear(C.coeffs, 0, DLM_N * sizeof(uint));
		signs = 0;

		for (i = 0; i < 8; ++i)
		{
			signs |= static_cast<ulong>(Signature[ofts + (DLM_N / 8) + i]) << (8 * i);
		}

		// extra sign bits are zero for strong unforgeability
		if ((signs >> 60) != 0)
		{
			ret = false;
		}

		if (ret == true)
		{
			mask = 1;

			for (i = 0; i < DLM_N / 8; ++i)
			{
				for (j = 0; j < 8; ++j)
				{
					if ((Signature[ofts + i] >> j) & 0x01)
					{
						C.coeffs[(8 * i) + j] = (signs & mask) ? DLM_Q - 1 : 1;
						mask <<= 1;
					}
				}
			}
		}
	}

	return ret;
}

void DLMN256Q8380417::UnPackSk(std::vector<byte> &Rho, std::vector<byte> &Key, std::vector<byte> &Tr, PolyVec &S1, PolyVec &S2, PolyVec &T0, const std::vector<byte> &Sk, uint Eta, size_t EtaPack)
{
	size_t i;
	size_t oftsk;

	MemoryTools::Copy(Sk, 0, Rho, 0, DLM_SEED_SIZE);
	oftsk = DLM_SEED_SIZE;
	MemoryTools::Copy(Sk, oftsk, Key, 0, DLM_SEED_SIZE);
	oftsk += DLM_SEED_SIZE;
	MemoryTools::Copy(Sk, oftsk, Tr, 0, DLM_CHR_SIZE);
	oftsk += DLM_CHR_SIZE;

	for (i = 0; i < S1.vec.size(); ++i)
	{
		PolyEtaUnpack(S1.vec[i], Sk, oftsk + (i * EtaPack), Eta);
	}

	oftsk += S1.vec.size() * EtaPack;

	for (i = 0; i < S2.vec.size(); ++i)
	{
		PolyEtaUnpack(S2.vec[i], Sk, oftsk + (i * EtaPack), Eta);
	}

	oftsk += S2.vec.size() * EtaPack;

	for (i = 0; i < S2.vec.size(); ++i)
	{
		PolyT0Unpack(T0.vec[i], Sk, oftsk + (i * DLM_POLT0_PACKED));
	}
}

uint DLMN256Q8380417::UseHint(uint A, uint Hint)
{
	uint a0;
	uint a1;

	a1 = Decompose(A, a0);

	if (Hint != 0)
	{
		if (a0 > DLM_Q)
		{
			a1 = (a1 + 1) & 0x0F;
		}
		else
		{
			a1 = (a1 - 1) & 0x0F;
		}
	}

	return a1;
}

void DLMN256Q8380417::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, DilithiumParameters Params)
{
	DlmParams cparams(Params);
	std::vector<byte> rho(DLM_SEED_SIZE);
	std::vector<byte> rhoprime(DLM_SEED_SIZE);
	std::vector<byte> seed(DLM_SEED_SIZE);
	std::vector<byte> tr(DLM_CHR_SIZE);
	std::vector<byte> key(DLM_SEED_SIZE);
	std::vector<PolyVec> mat(cparams.K);
	PolyVec s1(cparams.L);
	PolyVec s1hat(cparams.L);
	PolyVec s2(cparams.K);
	PolyVec t(cparams.K);
	PolyVec t0(cparams.K);
	PolyVec t1(cparams.K);
	size_t i;
	ushort nonce;

	for (i = 0; i < cparams.K; ++i)
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
		PolyUniformEta(s1.vec[i], rhoprime, nonce++, cparams.Eta);
	}
	for (i = 0; i < cparams.K; ++i)
	{
		PolyUniformEta(s2.vec[i], rhoprime, nonce++, cparams.Eta);
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
	gen.Generate(tr, 0, DLM_CHR_SIZE);
	PackSk(PrivateKey, rho, key, tr, s1, s2, t0, cparams.Eta, cparams.PolEtaPack);
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
	std::vector<byte> key(DLM_SEED_SIZE);
	std::vector<byte> mu(DLM_CHR_SIZE);
	std::vector<byte> rho(DLM_SEED_SIZE);
	std::vector<byte> tr(DLM_CHR_SIZE);
	std::vector<byte> tmps(DLM_CHR_SIZE + MSGLEN);
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
	size_t i;
	size_t j;
	uint n;
	ushort nonce;

	nonce = 0;
	Signature.resize(Message.size() + cparams.SignatureSize);

	for (i = 0; i < cparams.K; ++i)
	{
		mat[i] = PolyVec(cparams.L);
	}

	UnPackSk(rho, key, tr, s1, s2, t0, PrivateKey, cparams.Eta, cparams.PolEtaPack);

	// copy tr and message into the sm buffer,
	// backwards since m and sm can be equal in SUPERCOP API
	for (i = 1; i <= MSGLEN; ++i)
	{
		Signature[cparams.SignatureSize + MSGLEN - i] = Message[MSGLEN - i];
	}

	MemoryTools::Copy(tr, 0, Signature, cparams.SignatureSize - DLM_CHR_SIZE, DLM_CHR_SIZE);

	// compute CRH(tr, msg)
	MemoryTools::Copy(Signature, cparams.SignatureSize - DLM_CHR_SIZE, tmps, 0, DLM_CHR_SIZE + MSGLEN);
	XOF(tmps, 0, tmps.size(), mu, 0, DLM_CHR_SIZE, Keccak::KECCAK256_RATE_SIZE);

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

		if (PolyVecChkNorm(z, DLM_GAMMA1 - cparams.Beta) != 0)
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

		if (PolyVecChkNorm(wcs20, DLM_GAMMA2 - cparams.Beta) != 0)
		{
			continue;
		}

		for (i = 0; i < cparams.K; ++i)
		{
			for (j = 0; j < DLM_N; ++j)
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

		if (PolyVecChkNorm(ct0, DLM_GAMMA2) != 0)
		{
			continue;
		}

		PolyVecAdd(tmp, wcs2, ct0);
		PolyVecCSubq(tmp);
		n = PolyVecMakeHint(h, wcs2, tmp);

		if (n <= cparams.Omega)
		{
			break;
		}
	}

	// write signature
	PackSig(Signature, z, h, c, cparams.Omega);

	return Signature.size();
}

bool DLMN256Q8380417::Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, DilithiumParameters Params)
{
	DlmParams cparams(Params);
	const size_t MSGLEN = Signature.size() - cparams.SignatureSize;
	std::vector<byte> rho(DLM_SEED_SIZE);
	std::vector<byte> mu(DLM_CHR_SIZE);
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
	bool ret;

	ret = false;

	if (Signature.size() >= cparams.SignatureSize)
	{
		for (size_t i = 0; i < cparams.K; ++i)
		{
			mat[i] = PolyVec(cparams.L);
		}

		UnPackPk(rho, t1, PublicKey);

		if (UnPackSig(z, h, c, Signature, cparams.Omega) == true)
		{
			if (PolyVecChkNorm(z, DLM_GAMMA1 - cparams.Beta) == 0)
			{
				// compute CRH(CRH(rho, t1), msg) using m as 'playground' buffer
				MemoryTools::Copy(Message, 0, tmsg, 0, Message.size());

				if (Signature != tmsg)
				{
					for (i = 0; i < MSGLEN; ++i)
					{
						tmsg[cparams.SignatureSize + i] = Signature[cparams.SignatureSize + i];
					}
				}

				XOF(PublicKey, 0, cparams.PublicKeySize, tmsg, cparams.SignatureSize - DLM_CHR_SIZE, DLM_CHR_SIZE, Keccak::KECCAK256_RATE_SIZE);
				XOF(tmsg, cparams.SignatureSize - DLM_CHR_SIZE, DLM_CHR_SIZE + MSGLEN, mu, 0, DLM_CHR_SIZE, Keccak::KECCAK256_RATE_SIZE);

				// matrix-vector multiplication; compute Az - c2^dt1
				ExpandMatrix(mat, rho);
				PolyVecNtt(z);

				for (i = 0; i < cparams.K; ++i)
				{
					PolyVecPointwiseAccInvMontgomery(tmp1.vec[i], mat[i], z);
				}

				chat = c;
				PolyNtt(chat);
				PolyVecShiftL(t1, DLM_D);
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

				if (IntegerTools::Compare(c.coeffs, 0, cp.coeffs, 0, DLM_N))
				{
					// all good, copy msg, return success
					MemoryTools::Copy(Signature, cparams.SignatureSize, Message, 0, MSGLEN);
					ret = true;
				}
			}
		}
	}

	return ret;
}

void DLMN256Q8380417::Absorb(const std::vector<byte> &Input, std::array<ulong, 25> &State)
{
#if defined(CEX_SHAKE_STRONG)
	Keccak::AbsorbR48(Input, 0, Input.size(), Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, State);
#else
	Keccak::AbsorbR24(Input, 0, Input.size(), Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, State);
#endif
}

void DLMN256Q8380417::Squeeze(std::array<ulong, 25> &State, std::vector<byte> &Output, size_t Blocks)
{
#if defined(CEX_SHAKE_STRONG)
	Keccak::SqueezeR48(State, Output, 0, Blocks, Keccak::KECCAK256_RATE_SIZE);
#else
	Keccak::SqueezeR24(State, Output, 0, Blocks, Keccak::KECCAK256_RATE_SIZE);
#endif
}

void DLMN256Q8380417::XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
#if defined(CEX_SHAKE_STRONG)
	Keccak::XOFR48P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
#else
	Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
#endif
}

NAMESPACE_DILITHIUMEND
