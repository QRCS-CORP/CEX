#include "DLMNPolyMath.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_DILITHIUM

using Digest::Keccak;
using Utility::MemoryTools;

const uint DLMNPolyMath::Zetas[DILITHIUM_N] =
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

const uint DLMNPolyMath::ZetasInv[DILITHIUM_N] =
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

// ntt.c //

void DLMNPolyMath::InvNttFromInvMont(std::array<uint, 256> &P)
{
	const uint F = ((static_cast<ulong>(DILITHIUM_MONT) * DILITHIUM_MONT % DILITHIUM_Q) * (DILITHIUM_Q - 1) % DILITHIUM_Q) * ((DILITHIUM_Q - 1) >> 8) % DILITHIUM_Q;
	size_t j;
	size_t k;
	size_t len;
	size_t start;
	uint t;
	uint zeta;

	k = 0;

	for (len = 1; len < P.size(); len <<= 1)
	{
		for (start = 0; start < P.size(); start = j + len)
		{
			zeta = ZetasInv[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = P[j];
				P[j] = t + P[j + len];
				P[j + len] = t + (256 * DILITHIUM_Q) - P[j + len];
				P[j + len] = MontgomeryReduce(static_cast<ulong>(zeta) * P[j + len]);
			}
		}
	}

	for (j = 0; j < P.size(); ++j)
	{
		P[j] = MontgomeryReduce(static_cast<ulong>(F) * P[j]);
	}
}

void DLMNPolyMath::Ntt(std::array<uint, 256> &P)
{
	size_t j;
	size_t k;
	size_t len;
	size_t start;
	uint t;
	uint zeta;

	k = 1;

	for (len = 128; len > 0; len >>= 1)
	{
		for (start = 0; start < P.size(); start = j + len)
		{
			zeta = Zetas[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = MontgomeryReduce(static_cast<ulong>(zeta) * P[j + len]);
				P[j + len] = P[j] + (2 * DILITHIUM_Q) - t;
				P[j] = P[j] + t;
			}
		}
	}
}

// packing.c //

void DLMNPolyMath::PackPk(std::vector<byte> &Pk, const std::vector<byte> &Rho, const std::vector<std::array<uint, 256>> &T1, uint PolT1Packed)
{
	size_t i;

	MemoryTools::Copy(Rho, 0, Pk, 0, Rho.size());

	for (i = 0; i < T1.size(); ++i)
	{
		PolyT1Pack(Pk, Rho.size() + (i * PolT1Packed), T1[i]);
	}
}

void DLMNPolyMath::UnpackPk(std::vector<byte> &Rho, std::vector<std::array<uint, 256>> &T1, const std::vector<byte> &Pk, uint PolT1Packed)
{
	size_t i;
	size_t poff;

	MemoryTools::Copy(Pk, 0, Rho, 0, Rho.size());

	poff = Rho.size();

	for (i = 0; i < T1.size(); ++i)
	{
		PolyT1Unpack(T1[i], Pk, poff + (i * PolT1Packed));
	}
}

void DLMNPolyMath::PackSk(std::vector<byte> &Sk, const std::vector<byte> &Rho, const std::vector<byte> &Key, const std::vector<byte> &Tr, const std::vector<std::array<uint, 256>> &S1,
	const std::vector<std::array<uint, 256>> &S2, const std::vector<std::array<uint, 256>> &T0, uint Eta, uint PolTAPacked, uint PolT0Packed)
{
	size_t i;
	size_t soff;

	MemoryTools::Copy(Rho, 0, Sk, 0, Rho.size());
	soff = Rho.size();
	MemoryTools::Copy(Key, 0, Sk, soff, Key.size());
	soff += Key.size();
	MemoryTools::Copy(Tr, 0, Sk, soff, Tr.size());
	soff += Tr.size();

	for (i = 0; i < S1.size(); ++i)
	{
		PolyEtaPack(Sk, soff + (i * PolTAPacked), S1[i], Eta);
	}

	soff += S1.size() * PolTAPacked;

	for (i = 0; i < S2.size(); ++i)
	{
		PolyEtaPack(Sk, soff + (i * PolTAPacked), S2[i], Eta);
	}

	soff += T0.size() * PolTAPacked;

	for (i = 0; i < T0.size(); ++i)
	{
		PolyT0Pack(Sk, soff + (i * PolT0Packed), T0[i]);
	}
}

void DLMNPolyMath::UnpackSk(std::vector<byte> &Rho, std::vector<byte> &Key, std::vector<byte> &Tr, std::vector<std::array<uint, 256>> &S1, std::vector<std::array<uint, 256>> &S2,
	std::vector<std::array<uint, 256>> &T0, const std::vector<byte> &Sk, uint Eta, uint PolTAPacked, uint PolT0Packed)
{
	size_t i;
	size_t soff;

	MemoryTools::Copy(Sk, 0, Rho, 0, Rho.size());
	soff = Rho.size();
	MemoryTools::Copy(Sk, soff, Key, 0, Key.size());
	soff += Key.size();
	MemoryTools::Copy(Sk, soff, Tr, 0, Tr.size());
	soff += Tr.size();

	for (i = 0; i < S1.size(); ++i)
	{
		PolyEtaUnpack(S1[i], Sk, soff + (i * PolTAPacked), Eta);
	}

	soff += S1.size() * PolTAPacked;

	for (i = 0; i < S2.size(); ++i)
	{
		PolyEtaUnpack(S2[i], Sk, soff + (i * PolTAPacked), Eta);
	}

	soff += S2.size() * PolTAPacked;

	for (i = 0; i < T0.size(); ++i)
	{
		PolyT0Unpack(T0[i], Sk, soff + (i * PolT0Packed));
	}
}

void DLMNPolyMath::PackSig(std::vector<byte> &Sig, const std::vector<std::array<uint, 256>> &Z, const std::vector<std::array<uint, 256>> &H, const std::array<uint, 256> &C, uint Omega, uint PolZPacked)
{
	size_t i;
	size_t j;
	size_t k;
	size_t soff;
	ulong mask;
	ulong signs;

	for (i = 0; i < Z.size(); ++i)
	{
		PolyZPack(Sig, (i * PolZPacked), Z[i]);
	}

	soff = Z.size() * PolZPacked;

	// encode h 
	k = 0;

	for (i = 0; i < H.size(); ++i)
	{
		for (j = 0; j < DILITHIUM_N; ++j)
		{
			if (H[i][j] != 0)
			{
				Sig[soff + k] = static_cast<byte>(j);
				++k;
			}
		}

		Sig[soff + Omega + i] = static_cast<byte>(k);
	}

	while (k < Omega)
	{
		Sig[soff + k] = 0;
		++k;
	}

	soff += Omega + H.size();

	// encode c 
	signs = 0;
	mask = 1;

	for (i = 0; i < DILITHIUM_N / 8; ++i)
	{
		Sig[soff + i] = 0;

		for (j = 0; j < 8; ++j)
		{
			if (C[(8 * i) + j] != 0)
			{
				Sig[soff + i] |= (1U << j);

				if (C[(8 * i) + j] == (DILITHIUM_Q - 1))
				{
					signs |= mask;
				}

				mask <<= 1;
			}
		}
	}

	soff += DILITHIUM_N / 8;

	for (i = 0; i < 8; ++i)
	{
		Sig[soff + i] = signs >> (8 * i);
	}
}

int32_t DLMNPolyMath::UnpackSig(std::vector<std::array<uint, 256>> &Z, std::vector<std::array<uint, 256>> &H, std::array<uint, 256> &C, const std::vector<byte> &Sig, uint Omega, uint PolZPacked)
{
	ulong signs;
	size_t i;
	size_t j;
	size_t k;
	size_t soff;
	int32_t ret;

	ret = 0;

	for (i = 0; i < Z.size(); ++i)
	{
		PolyZUnpack(Z[i], Sig, (i * PolZPacked));
	}

	soff = Z.size() * PolZPacked;

	// decode h 
	k = 0;

	for (i = 0; i < H.size(); ++i)
	{
		MemoryTools::Clear(H[i], 0, H[i].size() * sizeof(uint));

		if (Sig[soff + Omega + i] < k || Sig[soff + Omega + i] > Omega)
		{
			ret = 1;
			break;
		}

		for (j = k; j < Sig[soff + Omega + i]; ++j)
		{
			// coefficients are ordered for strong unforgeability 
			if (j > k && Sig[soff + j] <= Sig[soff + j - 1])
			{
				ret = 1;
				break;
			}

			H[i][Sig[soff + j]] = 1;
		}

		if (ret != 0)
		{
			break;
		}

		k = Sig[soff + Omega + i];
	}

	if (ret == 0)
	{
		// extra indices are zero for strong unforgeability 
		for (j = k; j < Omega; ++j)
		{
			if (Sig[soff + j])
			{
				ret = 1;
				break;
			}
		}

		if (ret == 0)
		{
			soff += Omega + H.size();

			// decode c 
			MemoryTools::Clear(C, 0, C.size() * sizeof(uint));

			signs = 0;

			for (i = 0; i < 8; ++i)
			{
				signs |= static_cast<ulong>(Sig[soff + (DILITHIUM_N / 8) + i]) << (8 * i);
			}

			// extra sign bits are zero for strong unforgeability 
			if (signs >> 60)
			{
				ret = 1;
			}

			if (ret == 0)
			{
				for (i = 0; i < DILITHIUM_N / 8; ++i)
				{
					for (j = 0; j < 8; ++j)
					{
						if ((Sig[soff + i] >> j) & 0x01)
						{
							C[(8 * i) + j] = 1;
							C[(8 * i) + j] ^= static_cast<uint>(~(signs & 1) + 1) & (1 ^ (DILITHIUM_Q - 1));
							signs >>= 1;
						}
					}
				}
			}
		}
	}

	return ret;
}

// poly.c //

void DLMNPolyMath::PolyAdd(std::array<uint, 256> &C, const std::array<uint, 256> &A, const std::array<uint, 256> &B)
{
	size_t i;

	for (i = 0; i < C.size(); ++i)
	{
		C[i] = A[i] + B[i];
	}
}

int32_t DLMNPolyMath::PolyChkNorm(const std::array<uint, 256> &A, uint B)
{
	size_t i;
	int32_t s;
	int32_t t;

	// it is ok to leak which coefficient violates the bound since
	// the probability for each coefficient is independent of secret
	// data but we must not leak the sign of the centralized representative. 

	s = 0;

	for (i = 0; i < A.size(); ++i)
	{
		// absolute value of centralized representative 
		t = ((DILITHIUM_Q - 1) / 2) - A[i];
		t ^= (t >> 31);
		t = ((DILITHIUM_Q - 1) / 2) - t;

		if (static_cast<uint>(t) >= B)
		{
			s = 1;
			break;
		}
	}

	return s;
}

void DLMNPolyMath::PolyCSubQ(std::array<uint, 256> &A)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		A[i] = CSubQ(A[i]);
	}
}

void DLMNPolyMath::PolyDecompose(std::array<uint, 256> &A1, std::array<uint, 256> &A0, const std::array<uint, 256> &A)
{
	size_t i;

	for (i = 0; i < A1.size(); ++i)
	{
		A1[i] = Decompose(A[i], A0[i]);
	}
}

void DLMNPolyMath::PolyEtaPack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A, uint Eta)
{
	size_t i;
	std::array<byte, 8> t;

	if ((2 * Eta) <= 7)
	{
		for (i = 0; i < A.size() / 8; ++i)
		{
			t[0] = DILITHIUM_Q + Eta - A[(8 * i)];
			t[1] = DILITHIUM_Q + Eta - A[(8 * i) + 1];
			t[2] = DILITHIUM_Q + Eta - A[(8 * i) + 2];
			t[3] = DILITHIUM_Q + Eta - A[(8 * i) + 3];
			t[4] = DILITHIUM_Q + Eta - A[(8 * i) + 4];
			t[5] = DILITHIUM_Q + Eta - A[(8 * i) + 5];
			t[6] = DILITHIUM_Q + Eta - A[(8 * i) + 6];
			t[7] = DILITHIUM_Q + Eta - A[(8 * i) + 7];

			R[ROffset + (3 * i)] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
			R[ROffset + (3 * i) + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
			R[ROffset + (3 * i) + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
		}
	}
	else
	{
		for (i = 0; i < A.size() / 2; ++i)
		{
			t[0] = DILITHIUM_Q + Eta - A[(2 * i)];
			t[1] = DILITHIUM_Q + Eta - A[(2 * i) + 1];
			R[ROffset + i] = t[0] | (t[1] << 4);
		}
	}
}

void DLMNPolyMath::PolyEtaUnpack(std::array<uint, 256> &R, const std::vector<byte> &A, size_t AOffset, uint Eta)
{
	size_t i;

	if ((2 * Eta) <= 7)
	{
		for (i = 0; i < R.size() / 8; ++i)
		{
			R[(8 * i)] = A[AOffset + (3 * i)] &0x07;
			R[(8 * i) + 1] = (A[AOffset + (3 * i)] >> 3) &0x07;
			R[(8 * i) + 2] = ((A[AOffset + (3 * i)] >> 6) | (A[AOffset + (3 * i) + 1] << 2)) &0x07;
			R[(8 * i) + 3] = (A[AOffset + (3 * i) + 1] >> 1) &0x07;
			R[(8 * i) + 4] = (A[AOffset + (3 * i) + 1] >> 4) &0x07;
			R[(8 * i) + 5] = ((A[AOffset + (3 * i) + 1] >> 7) | (A[AOffset + (3 * i) + 2] << 1)) &0x07;
			R[(8 * i) + 6] = (A[AOffset + (3 * i) + 2] >> 2) &0x07;
			R[(8 * i) + 7] = (A[AOffset + (3 * i) + 2] >> 5) &0x07;

			R[(8 * i)] = DILITHIUM_Q + Eta - R[(8 * i)];
			R[(8 * i) + 1] = DILITHIUM_Q + Eta - R[(8 * i) + 1];
			R[(8 * i) + 2] = DILITHIUM_Q + Eta - R[(8 * i) + 2];
			R[(8 * i) + 3] = DILITHIUM_Q + Eta - R[(8 * i) + 3];
			R[(8 * i) + 4] = DILITHIUM_Q + Eta - R[(8 * i) + 4];
			R[(8 * i) + 5] = DILITHIUM_Q + Eta - R[(8 * i) + 5];
			R[(8 * i) + 6] = DILITHIUM_Q + Eta - R[(8 * i) + 6];
			R[(8 * i) + 7] = DILITHIUM_Q + Eta - R[(8 * i) + 7];
		}
	}
	else
	{
		for (i = 0; i < R.size() / 2; ++i)
		{
			R[(2 * i)] = A[AOffset + i] &0x0F;
			R[(2 * i) + 1] = A[AOffset + i] >> 4;
			R[(2 * i)] = DILITHIUM_Q + Eta - R[2 * i];
			R[(2 * i) + 1] = DILITHIUM_Q + Eta - R[(2 * i) + 1];
		}
	}
}

void DLMNPolyMath::PolyFreeze(std::array<uint, 256> &A)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		A[i] = Freeze(A[i]);
	}
}

void DLMNPolyMath::PolyInvNttMontgomery(std::array<uint, 256> &A)
{
	InvNttFromInvMont(A);
}

uint DLMNPolyMath::PolyMakeHint(std::array<uint, 256> &H, const std::array<uint, 256> &A0, const std::array<uint, 256> &A1)
{
	size_t i;
	uint s;

	s = 0;

	for (i = 0; i < H.size(); ++i)
	{
		H[i] = MakeHint(A0[i], A1[i]);
		s += H[i];
	}

	return s;
}

void DLMNPolyMath::PolyNtt(std::array<uint, 256> &A)
{
	Ntt(A);
}

void DLMNPolyMath::PolyPointwiseInvMontgomery(std::array<uint, 256> &C, const std::array<uint, 256> &A, const std::array<uint, 256> &B)
{
	size_t i;

	for (i = 0; i < C.size(); ++i)
	{
		C[i] = MontgomeryReduce(static_cast<ulong>(A[i]) * B[i]);
	}
}

void DLMNPolyMath::PolyPower2Round(std::array<uint, 256> &A1, std::array<uint, 256> &A0, const std::array<uint, 256> &A)
{
	size_t i;

	for (i = 0; i < A1.size(); ++i)
	{
		A1[i] = Power2Round(A[i], A0[i]);
	}
}

void DLMNPolyMath::PolyReduce(std::array<uint, 256> &A)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		A[i] = Reduce32(A[i]);
	}
}

void DLMNPolyMath::PolyShiftL(std::array<uint, 256> &A)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		A[i] <<= DILITHIUM_D;
	}
}

void DLMNPolyMath::PolySub(std::array<uint, 256> &C, const std::array<uint, 256> &A, const std::array<uint, 256> &B)
{
	size_t i;

	for (i = 0; i < C.size(); ++i)
	{
		C[i] = A[i] + (2 * DILITHIUM_Q) - B[i];
	}
}

void DLMNPolyMath::PolyT0Pack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A)
{
	size_t i;
	std::array<uint, 4> t;

	for (i = 0; i < A.size() / 4; ++i)
	{
		t[0] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - A[(4 * i)];
		t[1] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - A[(4 * i) + 1];
		t[2] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - A[(4 * i) + 2];
		t[3] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - A[(4 * i) + 3];

		R[ROffset + (7 * i)] = t[0];
		R[ROffset + (7 * i) + 1] = t[0] >> 8;
		R[ROffset + (7 * i) + 1] |= t[1] << 6;
		R[ROffset + (7 * i) + 2] = t[1] >> 2;
		R[ROffset + (7 * i) + 3] = t[1] >> 10;
		R[ROffset + (7 * i) + 3] |= t[2] << 4;
		R[ROffset + (7 * i) + 4] = t[2] >> 4;
		R[ROffset + (7 * i) + 5] = t[2] >> 12;
		R[ROffset + (7 * i) + 5] |= t[3] << 2;
		R[ROffset + (7 * i) + 6] = t[3] >> 6;
	}
}

void DLMNPolyMath::PolyT0Unpack(std::array<uint, 256> &R, const std::vector<byte> &A, size_t AOffset)
{
	size_t i;

	for (i = 0; i < R.size() / 4; ++i)
	{
		R[(4 * i)] = A[AOffset + (7 * i)];
		R[(4 * i)] |= static_cast<uint>(A[AOffset + (7 * i) + 1] &0x3F) << 8;

		R[(4 * i) + 1] = A[AOffset + (7 * i) + 1] >> 6;
		R[(4 * i) + 1] |= static_cast<uint>(A[AOffset + (7 * i) + 2]) << 2;
		R[(4 * i) + 1] |= static_cast<uint>(A[AOffset + (7 * i) + 3] &0x0F) << 10;

		R[(4 * i) + 2] = A[AOffset + (7 * i) + 3] >> 4;
		R[(4 * i) + 2] |= static_cast<uint>(A[AOffset + (7 * i) + 4]) << 4;
		R[(4 * i) + 2] |= static_cast<uint>(A[AOffset + (7 * i) + 5] &0x03) << 12;

		R[(4 * i) + 3] = A[AOffset + (7 * i) + 5] >> 2;
		R[(4 * i) + 3] |= static_cast<uint>(A[AOffset + (7 * i) + 6]) << 6;

		R[(4 * i)] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - R[(4 * i)];
		R[(4 * i) + 1] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - R[(4 * i) + 1];
		R[(4 * i) + 2] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - R[(4 * i) + 2];
		R[(4 * i) + 3] = DILITHIUM_Q + (1U << (DILITHIUM_D - 1)) - R[(4 * i) + 3];
	}
}

void DLMNPolyMath::PolyT1Pack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A)
{
	size_t i;

	for (i = 0; i < A.size() / 8; ++i)
	{
		R[ROffset + (9 * i)] = (A[(8 * i)] >> 0);
		R[ROffset + (9 * i) + 1] = (A[(8 * i)] >> 8) | (A[(8 * i) + 1] << 1);
		R[ROffset + (9 * i) + 2] = (A[(8 * i) + 1] >> 7) | (A[(8 * i) + 2] << 2);
		R[ROffset + (9 * i) + 3] = (A[(8 * i) + 2] >> 6) | (A[(8 * i) + 3] << 3);
		R[ROffset + (9 * i) + 4] = (A[(8 * i) + 3] >> 5) | (A[(8 * i) + 4] << 4);
		R[ROffset + (9 * i) + 5] = (A[(8 * i) + 4] >> 4) | (A[(8 * i) + 5] << 5);
		R[ROffset + (9 * i) + 6] = (A[(8 * i) + 5] >> 3) | (A[(8 * i) + 6] << 6);
		R[ROffset + (9 * i) + 7] = (A[(8 * i) + 6] >> 2) | (A[(8 * i) + 7] << 7);
		R[ROffset + (9 * i) + 8] = (A[(8 * i) + 7] >> 1);
	}
}

void DLMNPolyMath::PolyT1Unpack(std::array<uint, 256> &R, const std::vector<byte> &A, size_t AOffset)
{
	size_t i;

	for (i = 0; i < R.size() / 8; ++i)
	{
		R[(8 * i)] = ((A[AOffset + (9 * i)] >> 0) | (static_cast<uint>(A[AOffset + (9 * i) + 1]) << 8)) &0x000001FFUL;
		R[(8 * i) + 1] = ((A[AOffset + (9 * i) + 1] >> 1) | (static_cast<uint>(A[AOffset + (9 * i) + 2]) << 7)) &0x000001FFUL;
		R[(8 * i) + 2] = ((A[AOffset + (9 * i) + 2] >> 2) | (static_cast<uint>(A[AOffset + (9 * i) + 3]) << 6)) &0x000001FFUL;
		R[(8 * i) + 3] = ((A[AOffset + (9 * i) + 3] >> 3) | (static_cast<uint>(A[AOffset + (9 * i) + 4]) << 5)) &0x000001FFUL;
		R[(8 * i) + 4] = ((A[AOffset + (9 * i) + 4] >> 4) | (static_cast<uint>(A[AOffset + (9 * i) + 5]) << 4)) &0x000001FFUL;
		R[(8 * i) + 5] = ((A[AOffset + (9 * i) + 5] >> 5) | (static_cast<uint>(A[AOffset + (9 * i) + 6]) << 3)) &0x000001FFUL;
		R[(8 * i) + 6] = ((A[AOffset + (9 * i) + 6] >> 6) | (static_cast<uint>(A[AOffset + (9 * i) + 7]) << 2)) &0x000001FFUL;
		R[(8 * i) + 7] = ((A[AOffset + (9 * i) + 7] >> 7) | (static_cast<uint>(A[AOffset + (9 * i) + 8]) << 1)) &0x000001FFUL;
	}
}

void DLMNPolyMath::PolyUniform(std::array<uint, 256> &A, const std::vector<byte> &Seed, ushort Nonce)
{
	const size_t NBLKS = (769 + Keccak::KECCAK128_RATE_SIZE) / Keccak::KECCAK128_RATE_SIZE;
	std::vector<byte> buf((NBLKS * Keccak::KECCAK128_RATE_SIZE) + 2);
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state = { 0 };
	std::vector<byte> tmps(Seed.size() + 2);
	size_t buflen;
	size_t ctr;
	size_t i;
	size_t off;

	buflen = NBLKS * Keccak::KECCAK128_RATE_SIZE;

	MemoryTools::Copy(Seed, 0, tmps, 0, Seed.size());
	tmps[Seed.size()] = static_cast<byte>(Nonce);
	tmps[Seed.size() + 1] = Nonce >> 8;

	Keccak::AbsorbR24(tmps, 0, tmps.size(), Keccak::KECCAK128_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
	Keccak::SqueezeR24(state, buf, 0, NBLKS, Keccak::KECCAK128_RATE_SIZE);

	ctr = RejUniform(A, 0, A.size(), buf, buflen);

	while (ctr < DILITHIUM_N)
	{
		off = buflen % 3;

		for (i = 0; i < off; ++i)
		{
			buf[i] = buf[buflen - off + i];
		}

		buflen = Keccak::KECCAK128_RATE_SIZE + off;
		Keccak::SqueezeR24(state, buf, off, 1, Keccak::KECCAK128_RATE_SIZE);
		ctr += RejUniform(A, ctr, A.size() - ctr, buf, buflen);
	}
}

void DLMNPolyMath::PolyUniformEta(std::array<uint, 256> &A, const std::vector<byte> &Seed, ushort nonce, uint Eta, uint Seta)
{
	const size_t NBLKS = ((DILITHIUM_N / 2 * (1U << Seta)) / (2 * Eta + 1) + Keccak::KECCAK128_RATE_SIZE) / Keccak::KECCAK128_RATE_SIZE;
	std::vector<byte> buf(NBLKS * Keccak::KECCAK128_RATE_SIZE);
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state = { 0 };
	std::vector<byte> tmps(Seed.size() + 2);
	size_t buflen;
	size_t ctr;

	buflen = NBLKS * Keccak::KECCAK128_RATE_SIZE;

	MemoryTools::Copy(Seed, 0, tmps, 0, Seed.size());
	tmps[Seed.size()] = static_cast<byte>(nonce);
	tmps[Seed.size() + 1] = nonce >> 8;

	Keccak::AbsorbR24(tmps, 0, tmps.size(), Keccak::KECCAK128_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
	Keccak::SqueezeR24(state, buf, 0, NBLKS, Keccak::KECCAK128_RATE_SIZE);

	ctr = RejEta(A, 0, A.size(), buf, buflen, Eta);

	while (ctr < DILITHIUM_N)
	{
		Keccak::SqueezeR24(state, buf, 0, 1, Keccak::KECCAK128_RATE_SIZE);
		ctr += RejEta(A, ctr, A.size() - ctr, buf, Keccak::KECCAK128_RATE_SIZE, Eta);
	}
}

void DLMNPolyMath::PolyUniformGamma1M1(std::array<uint, 256> &A, const std::vector<byte> &Seed, ushort Nonce)
{
	const size_t NBLKS = (641 + Keccak::KECCAK256_RATE_SIZE) / Keccak::KECCAK256_RATE_SIZE;
	std::vector<byte> buf((NBLKS * Keccak::KECCAK256_RATE_SIZE) + 4);
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state = { 0 };
	std::vector<byte> tmps(Seed.size() + 2);
	size_t buflen;
	size_t ctr;
	size_t i;
	size_t off;

	MemoryTools::Copy(Seed, 0, tmps, 0, Seed.size());
	tmps[Seed.size()] = static_cast<byte>(Nonce);
	tmps[Seed.size() + 1] = Nonce >> 8;
	Keccak::AbsorbR24(tmps, 0, tmps.size(), Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
	Keccak::SqueezeR24(state, buf, 0, NBLKS, Keccak::KECCAK256_RATE_SIZE);

	buflen = NBLKS * Keccak::KECCAK256_RATE_SIZE;
	ctr = RejGamma1M1(A, 0, DILITHIUM_N, buf, buflen);

	while (ctr < DILITHIUM_N)
	{
		off = buflen % 5;

		for (i = 0; i < off; ++i)
		{
			buf[i] = buf[buflen - off + i];
		}

		buflen = Keccak::KECCAK256_RATE_SIZE + off;
		Keccak::SqueezeR24(state, buf, off, 1, Keccak::KECCAK256_RATE_SIZE);
		ctr += RejGamma1M1(A, ctr, DILITHIUM_N - ctr, buf, buflen);
	}
}

void DLMNPolyMath::PolyUseHint(std::array<uint, 256> &A, const std::array<uint, 256> &B, const std::array<uint, 256> &H)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		A[i] = UseHint(B[i], H[i]);
	}
}

void DLMNPolyMath::PolyW1Pack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A)
{
	size_t i;

	for (i = 0; i < A.size() / 2; ++i)
	{
		R[ROffset + i] = A[(2 * i)] | (A[(2 * i) + 1] << 4);
	}
}

void DLMNPolyMath::PolyZPack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A)
{
	std::array<uint, 2> t;
	size_t i;

	for (i = 0; i < A.size() / 2; ++i)
	{
		// map to {0,...,2*GAMMA1 - 2} 
		t[0] = DILITHIUM_GAMMA1 - 1 - A[(2 * i)];
		t[0] += (static_cast<int32_t>(t[0]) >> 31) &DILITHIUM_Q;
		t[1] = DILITHIUM_GAMMA1 - 1 - A[(2 * i) + 1];
		t[1] += (static_cast<int32_t>(t[1]) >> 31) &DILITHIUM_Q;

		R[ROffset + (5 * i)] = t[0];
		R[ROffset + (5 * i) + 1] = t[0] >> 8;
		R[ROffset + (5 * i) + 2] = t[0] >> 16;
		R[ROffset + (5 * i) + 2] |= t[1] << 4;
		R[ROffset + (5 * i) + 3] = t[1] >> 4;
		R[ROffset + (5 * i) + 4] = t[1] >> 12;
	}
}

void DLMNPolyMath::PolyZUnpack(std::array<uint, 256> &R, const std::vector<byte> &A, size_t AOffset)
{
	size_t i;

	for (i = 0; i < R.size() / 2; ++i)
	{
		R[(2 * i)] = A[AOffset + (5 * i)];
		R[(2 * i)] |= static_cast<uint>(A[AOffset + (5 * i) + 1]) << 8;
		R[(2 * i)] |= static_cast<uint>(A[AOffset + (5 * i) + 2] &0x0F) << 16;

		R[(2 * i) + 1] = A[AOffset + (5 * i) + 2] >> 4;
		R[(2 * i) + 1] |= static_cast<uint>(A[AOffset + (5 * i) + 3]) << 4;
		R[(2 * i) + 1] |= static_cast<uint>(A[AOffset + (5 * i) + 4]) << 12;

		R[(2 * i)] = DILITHIUM_GAMMA1 - 1 - R[(2 * i)];
		R[(2 * i)] += (static_cast<int32_t>(R[(2 * i)]) >> 31) &DILITHIUM_Q;
		R[(2 * i) + 1] = DILITHIUM_GAMMA1 - 1 - R[(2 * i) + 1];
		R[(2 * i) + 1] += (static_cast<int32_t>(R[(2 * i) + 1]) >> 31) &DILITHIUM_Q;
	}
}

size_t DLMNPolyMath::RejEta(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Buffer, size_t BufLength, uint Eta)
{
	size_t ctr;
	size_t pos;
	uint t0;
	uint t1;

	ctr = 0;
	pos = 0;

	while (ctr < ALength &&pos < BufLength)
	{
		if (Eta <= 3)
		{
			t0 = Buffer[pos] &0x07;
			t1 = Buffer[pos] >> 5;
			++pos;
		}
		else
		{
			t0 = Buffer[pos] &0x0F;
			t1 = Buffer[pos] >> 4;
			++pos;
		}

		if (t0 <= 2 * Eta)
		{
			A[AOffset + ctr] = DILITHIUM_Q + Eta - t0;
			++ctr;
		}

		if (t1 <= 2 * Eta &&ctr < ALength)
		{
			A[AOffset + ctr] = DILITHIUM_Q + Eta - t1;
			++ctr;
		}
	}

	return ctr;
}

size_t DLMNPolyMath::RejGamma1M1(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Buffer, size_t BufLength)
{
	size_t ctr;
	size_t pos;
	uint t0;
	uint t1;

	ctr = 0;
	pos = 0;

	while (ctr < ALength &&pos + 5 <= BufLength)
	{
		t0 = Buffer[pos];
		t0 |= static_cast<uint>(Buffer[pos + 1]) << 8;
		t0 |= static_cast<uint>(Buffer[pos + 2]) << 16;
		t0 &= 0x000FFFFFUL;

		t1 = Buffer[pos + 2] >> 4;
		t1 |= static_cast<uint>(Buffer[pos + 3]) << 4;
		t1 |= static_cast<uint>(Buffer[pos + 4]) << 12;

		pos += 5;

		if (t0 <= (2 * DILITHIUM_GAMMA1) - 2)
		{
			A[AOffset + ctr] = DILITHIUM_Q + DILITHIUM_GAMMA1 - 1 - t0;
			++ctr;
		}

		if (t1 <= (2 * DILITHIUM_GAMMA1) - 2 &&ctr < ALength)
		{
			A[AOffset + ctr] = DILITHIUM_Q + DILITHIUM_GAMMA1 - 1 - t1;
			++ctr;
		}
	}

	return ctr;
}

size_t DLMNPolyMath::RejUniform(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Buffer, size_t BufLength)
{
	size_t ctr;
	size_t pos;
	uint t;

	ctr = 0;
	pos = 0;

	while (ctr < ALength &&pos + 3 <= BufLength)
	{
		t = Buffer[pos];
		++pos;
		t |= static_cast<uint>(Buffer[pos]) << 8;
		++pos;
		t |= static_cast<uint>(Buffer[pos]) << 16;
		++pos;
		t &= 0x007FFFFFUL;

		if (t < DILITHIUM_Q)
		{
			A[AOffset + ctr] = t;
			++ctr;
		}
	}

	return ctr;
}

// polyvec.c //

void DLMNPolyMath::PolyVecAdd(std::vector<std::array<uint, 256>> &W, const std::vector<std::array<uint, 256>> &U, const std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < W.size(); ++i)
	{
		PolyAdd(W[i], U[i], V[i]);
	}
}

int32_t DLMNPolyMath::PolyVecChkNorm(const std::vector<std::array<uint, 256>> &V, uint bound)
{
	size_t i;
	int32_t r;

	r = 0;

	for (i = 0; i < V.size(); ++i)
	{
		if (PolyChkNorm(V[i], bound))
		{
			r = 1;
			break;
		}
	}

	return r;
}

void DLMNPolyMath::PolyVecCSubQ(std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < V.size(); ++i)
	{
		PolyCSubQ(V[i]);
	}
}

void DLMNPolyMath::PolyVecDecompose(std::vector<std::array<uint, 256>> &V1, std::vector<std::array<uint, 256>> &V0, const std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < V1.size(); ++i)
	{
		PolyDecompose(V1[i], V0[i], V[i]);
	}
}

void DLMNPolyMath::PolyVecFreeze(std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < V.size(); ++i)
	{
		PolyFreeze(V[i]);
	}
}

void DLMNPolyMath::PolyVecInvNttMontgomery(std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < V.size(); ++i)
	{
		PolyInvNttMontgomery(V[i]);
	}
}

uint DLMNPolyMath::PolyVecMakeHint(std::vector<std::array<uint, 256>> &H, const std::vector<std::array<uint, 256>> &V0, const std::vector<std::array<uint, 256>> &V1)
{
	size_t i;
	uint s;

	s = 0;

	for (i = 0; i < H.size(); ++i)
	{
		s += PolyMakeHint(H[i], V0[i], V1[i]);
	}

	return s;
}

void DLMNPolyMath::PolyVecNtt(std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < V.size(); ++i)
	{
		PolyNtt(V[i]);
	}
}

void DLMNPolyMath::PolyVecPointwiseAccInvMontgomery(std::array<uint, 256> &W, const std::vector<std::array<uint, 256>> &U, const std::vector<std::array<uint, 256>> &V)
{
	std::array<uint, 256> t;
	size_t i;

	PolyPointwiseInvMontgomery(W, U[0], V[0]);

	for (i = 1; i < U.size(); ++i)
	{
		PolyPointwiseInvMontgomery(t, U[i], V[i]);
		PolyAdd(W, W, t);
	}
}

void DLMNPolyMath::PolyVecPower2Round(std::vector<std::array<uint, 256>> &V1, std::vector<std::array<uint, 256>> &V0, const std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < V1.size(); ++i)
	{
		PolyPower2Round(V1[i], V0[i], V[i]);
	}
}

void DLMNPolyMath::PolyVecReduce(std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < V.size(); ++i)
	{
		PolyReduce(V[i]);
	}
}

void DLMNPolyMath::PolyVecShiftL(std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < V.size(); ++i)
	{
		PolyShiftL(V[i]);
	}
}

void DLMNPolyMath::PolyVecSub(std::vector<std::array<uint, 256>> &W, const std::vector<std::array<uint, 256>> &U, const std::vector<std::array<uint, 256>> &V)
{
	size_t i;

	for (i = 0; i < W.size(); ++i)
	{
		PolySub(W[i], U[i], V[i]);
	}
}

void DLMNPolyMath::PolyVecUseHint(std::vector<std::array<uint, 256>> &W, const std::vector<std::array<uint, 256>> &U, const std::vector<std::array<uint, 256>> &H)
{
	size_t i;

	for (i = 0; i < W.size(); ++i)
	{
		PolyUseHint(W[i], U[i], H[i]);
	}
}

// reduce.c //

uint DLMNPolyMath::CSubQ(uint A)
{
	A -= DILITHIUM_Q;
	A += (static_cast<int32_t>(A) >> 31) &DILITHIUM_Q;

	return A;
}

uint DLMNPolyMath::Freeze(uint A)
{

	A = Reduce32(A);
	A = CSubQ(A);

	return A;
}

uint DLMNPolyMath::MontgomeryReduce(ulong A)
{
	ulong t;

	t = A * DILITHIUM_QINV;
	t &= (1ULL << 32) - 1;
	t *= DILITHIUM_Q;
	t = A + t;
	t >>= 32;

	return t;
}

uint DLMNPolyMath::Reduce32(uint A)
{
	uint t;

	t = A &0x007FFFFFUL;
	A >>= 23;
	t += (A << 13) - A;

	return t;
}

// rounding.c //

uint DLMNPolyMath::Decompose(uint A, uint&A0)
{
	int32_t t;
	int32_t u;

	// centralized remainder mod ALPHA 
	t = A &0x0007FFFFL;
	t += (A >> 19) << 9;
	t -= (DILITHIUM_ALPHA / 2) + 1;
	t += (t >> 31) &DILITHIUM_ALPHA;
	t -= (DILITHIUM_ALPHA / 2) - 1;
	A -= t;

	// divide by ALPHA (possible to avoid) 
	u = A - 1;
	u >>= 31;
	A = (A >> 19) + 1;
	A -= u &1;

	// border case 
	A0 = DILITHIUM_Q + t - (A >> 4);
	A &= 0xF;

	return A;
}

uint DLMNPolyMath::MakeHint(const uint A0, const uint A1)
{
	uint r;

	r = 1;

	if (A0 <= DILITHIUM_GAMMA2 || A0 > DILITHIUM_Q - DILITHIUM_GAMMA2 || (A0 == DILITHIUM_Q - DILITHIUM_GAMMA2 &&A1 == 0))
	{
		r = 0;
	}

	return r;
}

uint DLMNPolyMath::Power2Round(uint A, uint&A0)
{
	int32_t t;

	// Centralized remainder mod 2^DILITHIUM_D 
	t = A &((1U << DILITHIUM_D) - 1);
	t -= (1U << (DILITHIUM_D - 1)) + 1;
	t += (t >> 31) &(1U << DILITHIUM_D);
	t -= (1U << (DILITHIUM_D - 1)) - 1;
	A0 = DILITHIUM_Q + t;
	A = (A - t) >> DILITHIUM_D;

	return A;
}

uint DLMNPolyMath::UseHint(const uint A, const uint Hint)
{
	uint a0;
	uint a1;

	a1 = Decompose(A, a0);

	if (Hint == 0)
	{
		return a1;
	}
	else if (a0 > DILITHIUM_Q)
	{
		return (a1 + 1) &0x0F;
	}
	else
	{
		return (a1 - 1) &0x0F;
	}
}

// sign.c //

void DLMNPolyMath::Challenge(std::array<uint, 256> &C, const std::vector<byte> &Mu, const std::vector<std::array<uint, 256>> &W1)
{
	std::vector<byte> inbuf(Mu.size() + W1.size() * DILITHIUM_POLW1_SIZE_PACKED);
	std::vector<byte> outbuf(Keccak::KECCAK256_RATE_SIZE);
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state = { 0 };
	ulong signs;
	size_t b;
	size_t i;
	size_t pos;

	MemoryTools::Copy(Mu, 0, inbuf, 0, Mu.size());

	for (i = 0; i < W1.size(); ++i)
	{
		PolyW1Pack(inbuf, Mu.size() + (i * DILITHIUM_POLW1_SIZE_PACKED), W1[i]);
	}

	Keccak::AbsorbR24(inbuf, 0, inbuf.size(), Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
	Keccak::SqueezeR24(state, outbuf, 0, 1, Keccak::KECCAK256_RATE_SIZE);
	signs = 0;

	for (i = 0; i < 8; ++i)
	{
		signs |= static_cast<ulong>(outbuf[i]) << 8 * i;
	}

	pos = 8;
	MemoryTools::Clear(C, 0, C.size() * sizeof(uint));

	for (i = 196; i < 256; ++i)
	{
		do
		{
			if (pos >= Keccak::KECCAK256_RATE_SIZE)
			{
				Keccak::SqueezeR24(state, outbuf, 0, 1, Keccak::KECCAK256_RATE_SIZE);
				pos = 0;
			}

			b = (size_t)outbuf[pos];
			++pos;
		} while (b > i);

		C[i] = C[b];
		C[b] = 1;
		C[b] ^= static_cast<uint>(~(signs &1) + 1) &(1 ^ (DILITHIUM_Q - 1));
		signs >>= 1;
	}
}

void DLMNPolyMath::ExpandMat(std::vector<std::vector<std::array<uint, 256>>> &Matrix, const std::vector<byte> &Rho)
{
	size_t i;
	size_t j;

	for (i = 0; i < Matrix.size(); ++i)
	{
		for (j = 0; j < Matrix[i].size(); ++j)
		{
			PolyUniform(Matrix[i][j], Rho, static_cast<ushort>(((i << 8) + j)));
		}
	}
}

NAMESPACE_DILITHIUMEND
