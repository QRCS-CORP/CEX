#include "NTRUPolyMath.h"

NAMESPACE_NTRUPRIME

//~~~Static Functions~~~//

void NTRUPolyMath::Decode(std::vector<ushort> &Output, size_t OutOffset, const std::vector<byte> &S, size_t SOffset, const std::vector<ushort> &M, size_t Length)
{
	std::vector<ushort> tmpr(0);
	std::vector<ushort> m2(0);
	std::vector<ushort> bottomr(0);
	std::vector<uint> bottomt(0);
	size_t i;
	uint m;
	uint r;
	uint r1;
	ushort r0;

	if (Length == 1)
	{
		if (M[0] == 1)
		{
			Output[OutOffset] = 0;
		}
		else if (M[0] <= 256)
		{
			Output[OutOffset] = U32ModU14(S[SOffset], M[0]);
		}
		else
		{
			Output[OutOffset] = U32ModU14(S[SOffset] + (static_cast<ushort>(S[SOffset + 1]) << 8), M[0]);
		}
	}

	if (Length > 1)
	{
		tmpr.resize((Length + 1) / 2);
		m2.resize((Length + 1) / 2);
		bottomr.resize(Length / 2);
		bottomt.resize(Length / 2);

		for (i = 0; i < Length - 1; i += 2)
		{
			m = M[i] * static_cast<uint>(M[i + 1]);

			if (m > 256 * 16383)
			{
				bottomt[i / 2] = 256 * 256;
				bottomr[i / 2] = S[SOffset] + (256 * S[SOffset + 1]);
				SOffset += 2;
				m2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
			}
			else if (m >= 16384)
			{
				bottomt[i / 2] = 256;
				bottomr[i / 2] = S[SOffset];
				SOffset += 1;
				m2[i / 2] = (m + 255) >> 8;
			}
			else
			{
				bottomt[i / 2] = 1;
				bottomr[i / 2] = 0;
				m2[i / 2] = m;
			}
		}

		if (i < Length)
		{
			m2[i / 2] = M[i];
		}

		Decode(tmpr, OutOffset, S, SOffset, m2, (Length + 1) / 2);

		for (i = 0; i < Length - 1; i += 2)
		{
			r = bottomr[i / 2];
			r += bottomt[i / 2] * tmpr[i / 2];
			U32DivModU14(r1, r0, r, M[i]);
			// only needed for invalid inputs
			r1 = U32ModU14(r1, M[i + 1]);
			Output[OutOffset] = r0;
			++OutOffset;
			Output[OutOffset] = r1;
			++OutOffset;
		}

		if (i < Length)
		{
			Output[OutOffset] = tmpr[i / 2];
			++OutOffset;
		}
	}
}

void NTRUPolyMath::Decrypt(std::vector<int8_t> &R, const std::vector<int16_t> &C, const std::vector<int8_t> &F, const std::vector<int8_t> &GInv, int32_t Q, int32_t W)
{
	// r = Decrypt(c,(f,ginv))
	const size_t P = R.size();
	std::vector<int16_t> cf(P);
	std::vector<int16_t> cf3(P);
	std::vector<int8_t> e(P);
	std::vector<int8_t> ev(P);
	size_t i;
	int mask;

	RqMultSmall(cf, C, F, Q);
	RqMult3(cf3, cf, Q);
	R3FromRq(e, cf3);
	R3Mult(ev, e, GInv);

	// 0 if weight NTRUP_W, else -1
	mask = WeightWMask(ev, W);

	for (i = 0; i < static_cast<size_t>(W); ++i)
	{
		R[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
	}

	for (i = W; i < P; ++i)
	{
		R[i] = ev[i] & ~mask;
	}
}

void NTRUPolyMath::Encode(std::vector<byte> &Output, size_t OutOffset, const std::vector<ushort> &R, const std::vector<ushort> &M, size_t Length)
{
	// 0 <= R[i] < M[i] < 16384

	std::vector<ushort> tmpm(0);
	std::vector<ushort> tmpr(0);
	size_t i;
	uint m;
	uint m0;
	uint r;
	ushort m16;
	ushort r16;

	if (Length == 1)
	{

		r16 = R[0];
		m16 = M[0];

		while (m16 > 1)
		{
			Output[OutOffset] = r16;
			++OutOffset;
			r16 >>= 8;
			m16 = (m16 + 255) >> 8;
		}
	}

	if (Length > 1)
	{
		tmpr.resize((Length + 1) / 2);
		tmpm.resize((Length + 1) / 2);

		for (i = 0; i < Length - 1; i += 2)
		{
			m0 = M[i];
			r = R[i] + (R[i + 1] * m0);
			m = M[i + 1] * m0;

			while (m >= 16384)
			{
				Output[OutOffset] = r;
				++OutOffset;
				r >>= 8;
				m = (m + 255) >> 8;
			}

			tmpr[i / 2] = r;
			tmpm[i / 2] = m;
		}

		if (i < Length)
		{
			tmpr[i / 2] = R[i];
			tmpm[i / 2] = M[i];
		}

		Encode(Output, OutOffset, tmpr, tmpm, (Length + 1) / 2);
	}
}

void NTRUPolyMath::Encrypt(std::vector<int16_t> &C, const std::vector<int8_t> &R, const std::vector<int16_t> &H, int32_t Q)
{
	// c = Encrypt(r,h)

	std::vector<int16_t> hr(R.size());

	RqMultSmall(hr, H, R, Q);
	Round(C, hr);
}

int16_t NTRUPolyMath::FqRecip(int16_t A1, int32_t Q)
{
	size_t i;
	int32_t ai;

	i = 1;
	ai = A1;

	while (i < static_cast<size_t>(Q - 2))
	{
		ai = FqFreeze(A1 * ai, Q);
		i += 1;
	}

	return static_cast<int16_t>(ai);
}

int NTRUPolyMath::R3Recip(std::vector<int8_t> &Output, const std::vector<int8_t> &Input)
{
	// returns 0 if recip succeeded; else -1

	const size_t P = Output.size();
	std::vector<int8_t> f(P + 1);
	std::vector<int8_t> g(P + 1);
	std::vector<int8_t> v(P + 1);
	std::vector<int8_t> r(P + 1);
	size_t i;
	size_t j;
	int32_t delta;
	int32_t sign;
	int32_t swap;
	int32_t t;

	for (i = 0; i < P + 1; ++i)
	{
		v[i] = 0;
	}

	for (i = 0; i < P + 1; ++i)
	{
		r[i] = 0;
	}

	r[0] = 1;

	for (i = 0; i < P; ++i)
	{
		f[i] = 0;
	}

	f[0] = 1;
	f[P - 1] = -1;
	f[P] = -1;

	for (i = 0; i < P; ++i)
	{
		g[P - 1 - i] = Input[i];
	}

	g[P] = 0;
	delta = 1;

	for (j = 0; j < 2 * P - 1; ++j)
	{
		i = P;

		do
		{
			v[i] = v[i - 1];
			--i;
		} while (i > 0);

		v[0] = 0;
		sign = -g[0] * f[0];
		swap = I16NegativeMask(-delta) & I16NonZeroMask(g[0]);
		delta ^= swap & (delta ^ -delta);
		delta += 1;

		for (i = 0; i < P + 1; ++i)
		{
			t = swap & (f[i] ^ g[i]);
			f[i] ^= t;
			g[i] ^= t;
			t = swap & (v[i] ^ r[i]);
			v[i] ^= t;
			r[i] ^= t;
		}

		for (i = 0; i < P + 1; ++i)
		{
			g[i] = F3Freeze(g[i] + (sign * f[i]));
		}

		for (i = 0; i < P + 1; ++i)
		{
			r[i] = F3Freeze(r[i] + (sign * v[i]));
		}

		for (i = 0; i < P; ++i)
		{
			g[i] = g[i + 1];
		}

		g[P] = 0;
	}

	sign = f[0];

	for (i = 0; i < P; ++i)
	{
		Output[i] = sign * v[P - 1 - i];
	}

	return I16NonZeroMask(delta);
}

void NTRUPolyMath::R3FromRq(std::vector<int8_t> &Output, const std::vector<int16_t> &R)
{
	// R3_fromR(R_fromRq(r))

	size_t i;

	for (i = 0; i < R.size(); ++i)
	{
		Output[i] = F3Freeze(R[i]);
	}
}

void NTRUPolyMath::R3Mult(std::vector<int8_t> &H, const std::vector<int8_t> &F, const std::vector<int8_t> &G)
{
	// h = f*g in the ring R3

	const size_t P = H.size();
	std::vector<int8_t> fg(P + P - 1);
	int8_t res;
	size_t i;
	size_t j;

	for (i = 0; i < P; ++i)
	{
		res = 0;

		for (j = 0; j <= i; ++j)
		{
			res = F3Freeze(res + F[j] * G[i - j]);
		}

		fg[i] = res;
	}

	for (i = P; i < P + P - 1; ++i)
	{
		res = 0;

		for (j = i - P + 1; j < P; ++j)
		{
			res = F3Freeze(res + F[j] * G[i - j]);
		}

		fg[i] = res;
	}

	for (i = P + P - 2; i >= P; --i)
	{
		fg[i - P] = F3Freeze(fg[i - P] + fg[i]);
		fg[i - P + 1] = F3Freeze(fg[i - P + 1] + fg[i]);
	}

	for (i = 0; i < P; ++i)
	{
		H[i] = fg[i];
	}
}

void NTRUPolyMath::RqMult3(std::vector<int16_t> &H, const std::vector<int16_t> &F, int32_t Q)
{
	// h = 3f in Rq
	size_t i;

	for (i = 0; i < H.size(); ++i)
	{
		H[i] = FqFreeze(3 * F[i], Q);
	}
}

void NTRUPolyMath::RqMultSmall(std::vector<int16_t> &H, const std::vector<int16_t> &F, const std::vector<int8_t> &G, int32_t Q)
{
	// h = f*g in the ring Rq
	const size_t P = H.size();
	std::vector<int16_t> fg(P + P - 1);
	size_t i;
	size_t j;
	int16_t res;

	for (i = 0; i < P; ++i)
	{
		res = 0;

		for (j = 0; j <= i; ++j)
		{
			res = FqFreeze(res + (F[j] * static_cast<int32_t>(G[i - j])), Q);
		}

		fg[i] = res;
	}

	for (i = P; i < P + P - 1; ++i)
	{
		res = 0;

		for (j = i - P + 1; j < P; ++j)
		{
			res = FqFreeze(res + (F[j] * static_cast<int32_t>(G[i - j])), Q);
		}

		fg[i] = res;
	}

	for (i = P + P - 2; i >= P; --i)
	{
		fg[i - P] = FqFreeze(fg[i - P] + fg[i], Q);
		fg[i - P + 1] = FqFreeze(fg[i - P + 1] + fg[i], Q);
	}

	for (i = 0; i < P; ++i)
	{
		H[i] = fg[i];
	}
}

void NTRUPolyMath::Round(std::vector<int16_t> &Output, const std::vector<int16_t> &A)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		Output[i] = A[i] - F3Freeze(A[i]);
	}
}

void NTRUPolyMath::RoundedDecode(std::vector<int16_t> &R, const std::vector<byte> &S, int32_t Q)
{
	const size_t P = R.size();
	const int16_t Q12 = static_cast<int16_t>((Q - 1) / 2);
	std::vector<ushort> tmpr(P);
	std::vector<ushort> tmpm(P);
	size_t i;

	for (i = 0; i < P; ++i)
	{
		tmpm[i] = (Q + 2) / 3;
	}

	Decode(tmpr, 0, S, 0, tmpm, P);

	for (i = 0; i < P; ++i)
	{
		R[i] = (tmpr[i] * 3) - Q12;
	}
}

void NTRUPolyMath::RoundedEncode(std::vector<byte> &S, const std::vector<int16_t> &R, int32_t Q)
{
	const size_t P = R.size();
	const int16_t Q12 = static_cast<int16_t>((Q - 1) / 2);
	std::vector<ushort> tmpm(P);
	std::vector<ushort> tmpr(P);
	size_t i;

	for (i = 0; i < P; ++i)
	{
		tmpr[i] = static_cast<ushort>(((R[i] + Q12) * 10923) >> 15);
	}

	for (i = 0; i < P; ++i)
	{
		tmpm[i] = static_cast<ushort>((Q + 2) / 3);
	}

	Encode(S, 0, tmpr, tmpm, P);
}

void NTRUPolyMath::RqDecode(std::vector<int16_t> &R, const std::vector<byte> &S, int32_t Q)
{
	const size_t P = R.size();
	const int16_t Q12 = static_cast<int16_t>((Q - 1) / 2);
	std::vector<ushort> tmpm(P);
	std::vector<ushort> tmpr(P);
	size_t i;

	for (i = 0; i < P; ++i)
	{
		tmpm[i] = Q;
	}

	Decode(tmpr, 0, S, 0, tmpm, P);

	for (i = 0; i < P; ++i)
	{
		R[i] = static_cast<int16_t>(tmpr[i]) - Q12;
	}
}

void NTRUPolyMath::RqEncode(std::vector<byte> &S, const std::vector<int16_t> &R, int32_t Q)
{
	const size_t P = R.size();
	const int16_t Q12 = static_cast<int16_t>((Q - 1) / 2);
	std::vector<ushort> tmpr(P);
	std::vector<ushort> tmpm(P);
	size_t i;

	for (i = 0; i < P; ++i)
	{
		tmpr[i] = R[i] + Q12;
	}

	for (i = 0; i < P; ++i)
	{
		tmpm[i] = Q;
	}

	Encode(S, 0, tmpr, tmpm, P);
}

int32_t NTRUPolyMath::RqRecip3(std::vector<int16_t> &Output, const std::vector<int8_t> &Input, int32_t Q)
{
	// out = 1/(3*in) in Rq: returns 0 if recip succeeded; else -1

	const size_t P = Output.size();
	std::vector<int16_t> f(P + 1);
	std::vector<int16_t> g(P + 1);
	std::vector<int16_t> v(P + 1);
	std::vector<int16_t> r(P + 1);
	size_t i;
	size_t j;
	int32_t delta;
	int32_t f0;
	int32_t g0;
	int32_t swap;
	int32_t t;
	int16_t scale;

	for (i = 0; i < P + 1; ++i)
	{
		v[i] = 0;
	}

	for (i = 0; i < P + 1; ++i)
	{
		r[i] = 0;
	}

	r[0] = FqRecip(3, Q);

	for (i = 0; i < P; ++i)
	{
		f[i] = 0;
	}

	f[0] = 1;
	f[P - 1] = -1;
	f[P] = -1;

	for (i = 0; i < P; ++i)
	{
		g[P - 1 - i] = Input[i];
	}

	g[P] = 0;
	delta = 1;

	for (j = 0; j < 2 * P - 1; ++j)
	{
		for (i = P; i > 0; --i)
		{
			v[i] = v[i - 1];
		}

		v[0] = 0;
		swap = I16NegativeMask(-delta) & I16NonZeroMask(g[0]);
		delta ^= swap & (delta ^ -delta);
		delta += 1;

		for (i = 0; i < P + 1; ++i)
		{
			t = swap & (f[i] ^ g[i]);
			f[i] ^= t;
			g[i] ^= t;
			t = swap & (v[i] ^ r[i]);
			v[i] ^= t;
			r[i] ^= t;
		}

		f0 = f[0];
		g0 = g[0];

		for (i = 0; i < P + 1; ++i)
		{
			g[i] = FqFreeze((f0 * g[i]) - (g0 * f[i]), Q);
		}

		for (i = 0; i < P + 1; ++i)
		{
			r[i] = FqFreeze(f0 * r[i] - (g0 * v[i]), Q);
		}

		for (i = 0; i < P; ++i)
		{
			g[i] = g[i + 1];
		}

		g[P] = 0;
	}

	scale = FqRecip(f[0], Q);

	for (i = 0; i < P; ++i)
	{
		Output[i] = FqFreeze(scale * static_cast<int32_t>(v[P - 1 - i]), Q);
	}

	return I16NonZeroMask(delta);
}

void NTRUPolyMath::SmallDecode(std::vector<int8_t> &F, const std::vector<byte> &S, size_t SOffset)
{
	size_t i;
	size_t fctr;
	byte x;

	fctr = 0;

	for (i = 0; i < F.size() / 4; ++i)
	{
		x = S[SOffset];
		++SOffset;
		F[fctr] = (static_cast<int8_t>(x & 0x03)) - 1;
		++fctr;
		x >>= 2;
		F[fctr] = (static_cast<int8_t>(x & 0x03)) - 1;
		++fctr;
		x >>= 2;
		F[fctr] = (static_cast<int8_t>(x & 0x03)) - 1;
		++fctr;
		x >>= 2;
		F[fctr] = (static_cast<int8_t>(x & 0x03)) - 1;
		++fctr;
	}

	x = S[SOffset];
	F[fctr] = (static_cast<int8_t>(x & 0x03)) - 1;
}

void NTRUPolyMath::SmallEncode(std::vector<byte> &S, size_t SOffset, const std::vector<int8_t> &F)
{
	int8_t x;
	size_t i;
	size_t fptr;
	size_t sptr;

	fptr = 0;
	sptr = SOffset;

	for (i = 0; i < F.size() / 4; ++i)
	{
		x = F[fptr] + 1;
		++fptr;
		x += (F[fptr] + 1) << 2;
		++fptr;
		x += (F[fptr] + 1) << 4;
		++fptr;
		x += (F[fptr] + 1) << 6;
		++fptr;
		S[sptr] = x;
		++sptr;
	}

	x = F[fptr] + 1;
	S[sptr] = x;
}

uint NTRUPolyMath::U32DivU14(uint X, ushort M)
{
	uint qt;
	ushort r;

	U32DivModU14(qt, r, X, M);

	return qt;
}

void NTRUPolyMath::U32DivModU14(uint& Q, ushort &R, uint X, ushort M)
{
	uint mask;
	uint qpart;
	uint v;

	v = 0x80000000UL;
	v /= M;
	// caller guarantees m > 0
	// caller guarantees m < 16384
	// vm <= 2^31 <= vm+m-1
	// xvm <= 2^31 x <= xvm+x(m-1)
	Q = 0;
	qpart = (X * static_cast<ulong>(v)) >> 31;
	// 2^31 qpart <= xv <= 2^31 qpart + 2^31-1
	// 2^31 qpart m <= xvm <= 2^31 qpart m + (2^31-1)m
	// 2^31 qpart m <= 2^31 x <= 2^31 qpart m + (2^31-1)m + x(m-1)
	// 0 <= 2^31 newx <= (2^31-1)m + x(m-1)
	// 0 <= newx <= (1-1/2^31)m + x(m-1)/2^31
	// 0 <= newx <= (1-1/2^31)(2^14-1) + (2^32-1)((2^14-1)-1)/2^31
	X -= qpart * M;
	Q += qpart;
	// x <= 49146
	qpart = (X * static_cast<ulong>(v)) >> 31;
	// 0 <= newx <= (1-1/2^31)m + x(m-1)/2^31
	// 0 <= newx <= m + 49146(2^14-1)/2^31
	// 0 <= newx <= m + 0.4
	// 0 <= newx <= m
	X -= qpart * M;
	Q += qpart;
	// x <= m
	X -= M;
	Q += 1;
	mask = ~(X >> 31) + 1;
	X += mask & static_cast<uint>(M);
	Q += mask;
	// x < m
	R = X;
}

ushort NTRUPolyMath::U32ModU14(uint X, ushort M)
{
	uint qt;
	ushort r;

	U32DivModU14(qt, r, X, M);

	return r;
}

int32_t NTRUPolyMath::WeightWMask(std::vector<int8_t> &R, int32_t W)
{
	// 0 if Weightw_is(r), else -1

	size_t i;
	int32_t weight;

	weight = 0;

	for (i = 0; i < R.size(); ++i)
	{
		weight += R[i] & 1;
	}

	return I16NonZeroMask(weight - W);
}

NAMESPACE_NTRUPRIMEEND
