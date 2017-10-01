// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_POLYMATH_H
#define CEX_POLYMATH_H

#include "CexDomain.h"

#if defined(__AVX512__)
#	include "UInt512.h"
#elif defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_UTILITY

/**
* \internal
*/

/// <summary>
/// Internal class used by RingLWE
/// </summary>
class PolyMath
{
public:

	template <class T>
	inline static T Abs(T &V)
	{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		return T::Abs(V);
#else
		T mask = V >> ((sizeof(T) * 8) - 1);
		return (V ^ mask) - mask;
#endif
	}

	template <typename Array, class T>
	inline static void Add(Array &R, const Array &A, const Array &B, int Q)
	{
		const T VN(5);

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		const size_t VULSZE = T::size() / sizeof(uint);
		std::array<uint, VULSZE> tmpR;
		const T NQ(Q);
		T tmpA, tmpB;
#else
		const size_t VULSZE = 1;
#endif

		for (size_t i = 0; i < R.size(); i += VULSZE)
		{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	if defined(__AVX512__)
			tmpA.Load(A[i + 15], A[i + 14], A[i + 13], A[i + 12], A[i + 11], A[i + 10], A[i + 9], A[i + 8], A[i + 7], A[i + 6], A[i + 5], A[i + 4], A[i + 3], A[i + 2], A[i + 1], A[i]);
			tmpB.Load(B[i + 15], B[i + 14], B[i + 13], B[i + 12], B[i + 11], B[i + 10], B[i + 9], B[i + 8], B[i + 7], B[i + 6], B[i + 5], B[i + 4], B[i + 3], B[i + 2], B[i + 1], B[i]);
#	elif defined(__AVX2__)
			tmpA.Load(A[i + 7], A[i + 6], A[i + 5], A[i + 4], A[i + 3], A[i + 2], A[i + 1], A[i]);
			tmpB.Load(B[i + 7], B[i + 6], B[i + 5], B[i + 4], B[i + 3], B[i + 2], B[i + 1], B[i]);
#	elif defined(__AVX__) 
			tmpA.Load(A[i + 3], A[i + 2], A[i + 1], A[i]);
			tmpB.Load(B[i + 3], B[i + 2], B[i + 1], B[i]);
#	endif

			T VF(tmpA + tmpB);
			T VU = (VF * VN) >> 16;
			VU *= NQ;
			VF -= VU;
			VF.Store(tmpR, 0);

			for (size_t j = 0; j < VULSZE; ++j)
			{
				R[j + i] = static_cast<ushort>(tmpR[j]);
			}
#else
			T F = A[i] + B[i];
			uint U = ((uint)F * VN) >> 16;
			U *= Q;
			F -= U;
			R[i] = F;
#endif
		}
	}

	template <typename Array>
	inline static void BitReverse(Array &P)
	{
		uint r;
		ushort tmp;

		const ushort BITREV[1024] =
		{
			0, 512, 256, 768, 128, 640, 384, 896, 64, 576, 320, 832, 192, 704, 448, 960, 32, 544, 288, 800, 160, 672, 416, 928, 96, 608, 352, 864, 224, 736, 480, 992,
			16, 528, 272, 784, 144, 656, 400, 912, 80, 592, 336, 848, 208, 720, 464, 976, 48, 560, 304, 816, 176, 688, 432, 944, 112, 624, 368, 880, 240, 752, 496, 1008,
			8, 520, 264, 776, 136, 648, 392, 904, 72, 584, 328, 840, 200, 712, 456, 968, 40, 552, 296, 808, 168, 680, 424, 936, 104, 616, 360, 872, 232, 744, 488, 1000,
			24, 536, 280, 792, 152, 664, 408, 920, 88, 600, 344, 856, 216, 728, 472, 984, 56, 568, 312, 824, 184, 696, 440, 952, 120, 632, 376, 888, 248, 760, 504, 1016,
			4, 516, 260, 772, 132, 644, 388, 900, 68, 580, 324, 836, 196, 708, 452, 964, 36, 548, 292, 804, 164, 676, 420, 932, 100, 612, 356, 868, 228, 740, 484, 996,
			20, 532, 276, 788, 148, 660, 404, 916, 84, 596, 340, 852, 212, 724, 468, 980, 52, 564, 308, 820, 180, 692, 436, 948, 116, 628, 372, 884, 244, 756, 500, 1012,
			12, 524, 268, 780, 140, 652, 396, 908, 76, 588, 332, 844, 204, 716, 460, 972, 44, 556, 300, 812, 172, 684, 428, 940, 108, 620, 364, 876, 236, 748, 492, 1004,
			28, 540, 284, 796, 156, 668, 412, 924, 92, 604, 348, 860, 220, 732, 476, 988, 60, 572, 316, 828, 188, 700, 444, 956, 124, 636, 380, 892, 252, 764, 508, 1020,
			2, 514, 258, 770, 130, 642, 386, 898, 66, 578, 322, 834, 194, 706, 450, 962, 34, 546, 290, 802, 162, 674, 418, 930, 98, 610, 354, 866, 226, 738, 482, 994,
			18, 530, 274, 786, 146, 658, 402, 914, 82, 594, 338, 850, 210, 722, 466, 978, 50, 562, 306, 818, 178, 690, 434, 946, 114, 626, 370, 882, 242, 754, 498, 1010,
			10, 522, 266, 778, 138, 650, 394, 906, 74, 586, 330, 842, 202, 714, 458, 970, 42, 554, 298, 810, 170, 682, 426, 938, 106, 618, 362, 874, 234, 746, 490, 1002,
			26, 538, 282, 794, 154, 666, 410, 922, 90, 602, 346, 858, 218, 730, 474, 986, 58, 570, 314, 826, 186, 698, 442, 954, 122, 634, 378, 890, 250, 762, 506, 1018,
			6, 518, 262, 774, 134, 646, 390, 902, 70, 582, 326, 838, 198, 710, 454, 966, 38, 550, 294, 806, 166, 678, 422, 934, 102, 614, 358, 870, 230, 742, 486, 998,
			22, 534, 278, 790, 150, 662, 406, 918, 86, 598, 342, 854, 214, 726, 470, 982, 54, 566, 310, 822, 182, 694, 438, 950, 118, 630, 374, 886, 246, 758, 502, 1014,
			14, 526, 270, 782, 142, 654, 398, 910, 78, 590, 334, 846, 206, 718, 462, 974, 46, 558, 302, 814, 174, 686, 430, 942, 110, 622, 366, 878, 238, 750, 494, 1006,
			30, 542, 286, 798, 158, 670, 414, 926, 94, 606, 350, 862, 222, 734, 478, 990, 62, 574, 318, 830, 190, 702, 446, 958, 126, 638, 382, 894, 254, 766, 510, 1022,
			1, 513, 257, 769, 129, 641, 385, 897, 65, 577, 321, 833, 193, 705, 449, 961, 33, 545, 289, 801, 161, 673, 417, 929, 97, 609, 353, 865, 225, 737, 481, 993,
			17, 529, 273, 785, 145, 657, 401, 913, 81, 593, 337, 849, 209, 721, 465, 977, 49, 561, 305, 817, 177, 689, 433, 945, 113, 625, 369, 881, 241, 753, 497, 1009,
			9, 521, 265, 777, 137, 649, 393, 905, 73, 585, 329, 841, 201, 713, 457, 969, 41, 553, 297, 809, 169, 681, 425, 937, 105, 617, 361, 873, 233, 745, 489, 1001,
			25, 537, 281, 793, 153, 665, 409, 921, 89, 601, 345, 857, 217, 729, 473, 985, 57, 569, 313, 825, 185, 697, 441, 953, 121, 633, 377, 889, 249, 761, 505, 1017,
			5, 517, 261, 773, 133, 645, 389, 901, 69, 581, 325, 837, 197, 709, 453, 965, 37, 549, 293, 805, 165, 677, 421, 933, 101, 613, 357, 869, 229, 741, 485, 997,
			21, 533, 277, 789, 149, 661, 405, 917, 85, 597, 341, 853, 213, 725, 469, 981, 53, 565, 309, 821, 181, 693, 437, 949, 117, 629, 373, 885, 245, 757, 501, 1013,
			13, 525, 269, 781, 141, 653, 397, 909, 77, 589, 333, 845, 205, 717, 461, 973, 45, 557, 301, 813, 173, 685, 429, 941, 109, 621, 365, 877, 237, 749, 493, 1005,
			29, 541, 285, 797, 157, 669, 413, 925, 93, 605, 349, 861, 221, 733, 477, 989, 61, 573, 317, 829, 189, 701, 445, 957, 125, 637, 381, 893, 253, 765, 509, 1021,
			3, 515, 259, 771, 131, 643, 387, 899, 67, 579, 323, 835, 195, 707, 451, 963, 35, 547, 291, 803, 163, 675, 419, 931, 99, 611, 355, 867, 227, 739, 483, 995,
			19, 531, 275, 787, 147, 659, 403, 915, 83, 595, 339, 851, 211, 723, 467, 979, 51, 563, 307, 819, 179, 691, 435, 947, 115, 627, 371, 883, 243, 755, 499, 1011,
			11, 523, 267, 779, 139, 651, 395, 907, 75, 587, 331, 843, 203, 715, 459, 971, 43, 555, 299, 811, 171, 683, 427, 939, 107, 619, 363, 875, 235, 747, 491, 1003,
			27, 539, 283, 795, 155, 667, 411, 923, 91, 603, 347, 859, 219, 731, 475, 987, 59, 571, 315, 827, 187, 699, 443, 955, 123, 635, 379, 891, 251, 763, 507, 1019,
			7, 519, 263, 775, 135, 647, 391, 903, 71, 583, 327, 839, 199, 711, 455, 967, 39, 551, 295, 807, 167, 679, 423, 935, 103, 615, 359, 871, 231, 743, 487, 999,
			23, 535, 279, 791, 151, 663, 407, 919, 87, 599, 343, 855, 215, 727, 471, 983, 55, 567, 311, 823, 183, 695, 439, 951, 119, 631, 375, 887, 247, 759, 503, 1015,
			15, 527, 271, 783, 143, 655, 399, 911, 79, 591, 335, 847, 207, 719, 463, 975, 47, 559, 303, 815, 175, 687, 431, 943, 111, 623, 367, 879, 239, 751, 495, 1007,
			31, 543, 287, 799, 159, 671, 415, 927, 95, 607, 351, 863, 223, 735, 479, 991, 63, 575, 319, 831, 191, 703, 447, 959, 127, 639, 383, 895, 255, 767, 511, 1023
		};

		for (size_t i = 0; i < P.size(); ++i)
		{
			r = BITREV[i];
			if (i < r)
			{
				tmp = P[i];
				P[i] = P[r];
				P[r] = tmp;
			}
		}
	}

	template <typename Array, class T>
	inline static void Mul(Array &R, const Array &Factors, int Q, uint QInv, uint RLog)
	{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		const size_t VULSZE = T::size() / sizeof(uint);
		std::array<uint, VULSZE> tmpR;
		T tmpP, tmpF;
#else
		const size_t VULSZE = 1;
#endif

		for (size_t i = 0; i < R.size(); i += VULSZE)
		{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	if defined(__AVX512__)
			tmpP.Load(R[i + 15], R[i + 14], R[i + 13], R[i + 12], R[i + 11], R[i + 10], R[i + 9], R[i + 8], R[i + 7], R[i + 6], R[i + 5], R[i + 4], R[i + 3], R[i + 2], R[i + 1], R[i]);
			tmpF.Load(Factors[i + 15], Factors[i + 14], Factors[i + 13], Factors[i + 12], Factors[i + 11], Factors[i + 10], Factors[i + 9], Factors[i + 8], Factors[i + 7], Factors[i + 6], Factors[i + 5], Factors[i + 4], Factors[i + 3], Factors[i + 2], Factors[i + 1], Factors[i]);
#	elif defined(__AVX2__)
			tmpP.Load(R[i + 7], R[i + 6], R[i + 5], R[i + 4], R[i + 3], R[i + 2], R[i + 1], R[i]);
			tmpF.Load(Factors[i + 7], Factors[i + 6], Factors[i + 5], Factors[i + 4], Factors[i + 3], Factors[i + 2], Factors[i + 1], Factors[i]);
#	elif defined(__AVX__) 
			tmpP.Load(R[i + 3], R[i + 2], R[i + 1], R[i]);
			tmpF.Load(Factors[i + 3], Factors[i + 2], Factors[i + 1], Factors[i]);
#	endif

			T a = tmpP * tmpF;
			T u = (a * T(QInv));
			u &= ((T::ONE() << RLog) - T::ONE());
			u *= T(Q);
			a += u;
			a >>= 18;
			a.Store(tmpR, 0);

			for (size_t j = 0; j < VULSZE; ++j)
			{
				R[j + i] = static_cast<ushort>(tmpR[j]);
			}
#else
			T a = R[i] * Factors[i];
			T u = (a * QInv);
			u &= ((1 << RLog) - 1);
			u *= Q;
			a += u;
			R[i] = a >> 18;
#endif
		}
	}
};

NAMESPACE_UTILITYEND
#endif

