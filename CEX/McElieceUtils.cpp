#include "McElieceUtils.h"

NAMESPACE_MCELIECE

//~~~Public Functions~~~//

ushort McElieceUtils::Diff(ushort X, ushort Y)
{
	uint t;
	
	t = static_cast<uint>(X ^ Y);
	t = ((t - 1) >> 20) ^ 0xFFFUL;

	return static_cast<ushort>(t);
}

ushort McElieceUtils::Invert(ushort X, size_t Degree)
{
	ushort out;
	ushort tmpa;
	ushort tmpb;

	out = X;
	out = Square(out, Degree);
	tmpa = Multiply(out, X, Degree);
	out = Square(tmpa, Degree);
	out = Square(out, Degree);
	tmpb = Multiply(out, tmpa, Degree);
	out = Square(tmpb, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Multiply(out, tmpb, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Multiply(out, tmpa, Degree);
	out = Square(out, Degree);
	out = Multiply(out, X, Degree);

	return Square(out, Degree);
}

ulong McElieceUtils::MaskNonZero64(ushort X)
{
	ulong ret;

	ret = X;
	ret -= 1;
	ret >>= 63;
	ret -= 1;

	return ret;
}

ulong McElieceUtils::MaskLeq64(ushort X, ushort Y)
{
	ulong ret;
	ulong tmpa;
	ulong tmpb;

	tmpa = X;
	tmpb = Y;
	ret = tmpb - tmpa;
	ret >>= 63;
	ret -= 1;

	return ret;
}

ushort McElieceUtils::Multiply(ushort X, ushort Y, size_t Degree)
{
	size_t i;
	uint t;
	uint t0;
	uint t1;
	uint tmp;

	t0 = X;
	t1 = Y;
	tmp = t0 * (t1 & 1);

	for (i = 1; i < Degree; ++i)
	{
		tmp ^= (t0 * (t1 & (1UL << i)));
	}

	t = tmp & 0x7FC000UL;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	t = tmp & 0x3000UL;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	return static_cast<ushort>(tmp & ((1UL << Degree) - 1));
}

ushort McElieceUtils::Square(ushort X, size_t Degree)
{
	static const std::array<uint, 4> B =
	{
		0x55555555UL, 0x33333333UL, 0x0F0F0F0FUL, 0x00FF00FFUL
	};

	uint t;
	uint y;

	y = X;
	y = (y | (y << 8)) & B[3];
	y = (y | (y << 4)) & B[2];
	y = (y | (y << 2)) & B[1];
	y = (y | (y << 1)) & B[0];

	t = y & 0x7FC000UL;
	y ^= t >> 9;
	y ^= t >> 12;

	t = y & 0x3000UL;
	y ^= t >> 9;
	y ^= t >> 12;

	return static_cast<ushort>(y & ((1 << Degree) - 1));
}

NAMESPACE_MCELIECEEND
