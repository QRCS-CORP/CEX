#ifndef CEXTEST_TESTFILES_H
#define CEXTEST_TESTFILES_H

#include <string>

namespace Test
{
	namespace TestFiles
	{
		namespace AESAVS
		{
			const std::string AESCBC128_VARKEY = "../../Test/Vectors/AESAVS/CBC/KAT/CBCVarKey128.rsp";
			const std::string AESCBC256_VARKEY = "../../Test/Vectors/AESAVS/CBC/KAT/CBCVarKey256.rsp";
			const std::string AESCBC128_VARTXT = "../../Test/Vectors/AESAVS/CBC/KAT/CBCVarTxt128.rsp";
			const std::string AESCBC256_VARTXT = "../../Test/Vectors/AESAVS/CBC/KAT/CBCVarTxt256.rsp";
			const std::string AESECB128_VARKEY = "../../Test/Vectors/AESAVS/ECB/KAT/ECBVarKey128.rsp";
			const std::string AESECB256_VARKEY = "../../Test/Vectors/AESAVS/ECB/KAT/ECBVarKey256.rsp";
			const std::string AESECB128_VARTXT = "../../Test/Vectors/AESAVS/ECB/KAT/ECBVarTxt128.rsp";
			const std::string AESECB256_VARTXT = "../../Test/Vectors/AESAVS/ECB/KAT/ECBVarTxt256.rsp";
			const std::string AESCBC128_MCT = "../../Test/Vectors/AESAVS/CBC/MCT/CBCMCT128.rsp";
			const std::string AESCBC256_MCT = "../../Test/Vectors/AESAVS/CBC/MCT/CBCMCT256.rsp";
			const std::string AESECB128_MCT = "../../Test/Vectors/AESAVS/ECB/MCT/ECBMCT128.rsp";
			const std::string AESECB256_MCT = "../../Test/Vectors/AESAVS/ECB/MCT/ECBMCT256.rsp";
			const std::string AESCBC128_MMT = "../../Test/Vectors/AESAVS/CBC/MMT/CBCMMT128.rsp";
			const std::string AESCBC256_MMT = "../../Test/Vectors/AESAVS/CBC/MMT/CBCMMT256.rsp";
			const std::string AESECB128_MMT = "../../Test/Vectors/AESAVS/ECB/MMT/ECBMMT128.rsp";
			const std::string AESECB256_MMT = "../../Test/Vectors/AESAVS/ECB/MMT/ECBMMT256.rsp";
		}

		namespace Blake2Kat
		{
			const std::string BLAKE2SKAT = "../../Test/Vectors/Blake2/blake2s-kat.txt";
			const std::string BLAKE2SPKAT = "../../Test/Vectors/Blake2/blake2sp-kat.txt";
			const std::string BLAKE2BKAT = "../../Test/Vectors/Blake2/blake2b-kat.txt";
			const std::string BLAKE2BPKAT = "../../Test/Vectors/Blake2/blake2bp-kat.txt";
		}

		namespace Nessie
		{
			const std::string SERPENTCTEXT128 = "../../Test/Vectors/Nessie/serpentcipher128.txt";
			const std::string SERPENTCTEXT192 = "../../Test/Vectors/Nessie/serpentcipher192.txt";
			const std::string SERPENTCTEXT256 = "../../Test/Vectors/Nessie/serpentcipher256.txt";
			const std::string SERPENTKEY128 = "../../Test/Vectors/Nessie/serpentkey128.txt";
			const std::string SERPENTKEY192 = "../../Test/Vectors/Nessie/serpentkey192.txt";
			const std::string SERPENTKEY256 = "../../Test/Vectors/Nessie/serpentkey256.txt";
			const std::string SERPENTM100X128 = "../../Test/Vectors/Nessie/serpentmonte100-128.txt";
			const std::string SERPENTM100X192 = "../../Test/Vectors/Nessie/serpentmonte100-192.txt";
			const std::string SERPENTM100X256 = "../../Test/Vectors/Nessie/serpentmonte100-256.txt";
			const std::string SERPENTM1000X128 = "../../Test/Vectors/Nessie/serpentmonte1000-128.txt";
			const std::string SERPENTM1000X192 = "../../Test/Vectors/Nessie/serpentmonte1000-192.txt";
			const std::string SERPENTM1000X256 = "../../Test/Vectors/Nessie/serpentmonte1000-256.txt";
			const std::string SERPENTPTEXT128 = "../../Test/Vectors/Nessie/serpentplain128.txt";
			const std::string SERPENTPTEXT192 = "../../Test/Vectors/Nessie/serpentplain192.txt";
			const std::string SERPENTPTEXT256 = "../../Test/Vectors/Nessie/serpentplain256.txt";
		}

		namespace NISTPQ3
		{
			const std::string DILITHIUM2544 = "../../Test/Vectors/NPQCR3/dilithium-2544.rsp";
			const std::string DILITHIUM4016 = "../../Test/Vectors/NPQCR3/dilithium-4016.rsp";
			const std::string DILITHIUM4880 = "../../Test/Vectors/NPQCR3/dilithium-4880.rsp";
			const std::string KYBER1632 = "../../Test/Vectors/NPQCR3/kyber-1632.rsp";
			const std::string KYBER2400 = "../../Test/Vectors/NPQCR3/kyber-2400.rsp";
			const std::string KYBER3168 = "../../Test/Vectors/NPQCR3/kyber-3168.rsp";
			const std::string KYBER3936 = "../../Test/Vectors/NPQCR3/kyber-3936.rsp";
			const std::string MCELIECE460896 = "../../Test/Vectors/NPQCR3/mceliece-460896.rsp";
			const std::string MCELIECE6688128 = "../../Test/Vectors/NPQCR3/mceliece-6688128.rsp";
			const std::string MCELIECE6960119 = "../../Test/Vectors/NPQCR3/mceliece-6960119.rsp";
			const std::string MCELIECE8192128 = "../../Test/Vectors/NPQCR3/mceliece-8192128.rsp";
			const std::string SPHINCSPLUS128F = "../../Test/Vectors/NPQCR3/sphincs-shake256-128f-robust.rsp";
			const std::string SPHINCSPLUS128S = "../../Test/Vectors/NPQCR3/sphincs-shake256-128s-robust.rsp";
			const std::string SPHINCSPLUS192F = "../../Test/Vectors/NPQCR3/sphincs-shake256-192f-robust.rsp";
			const std::string SPHINCSPLUS192S = "../../Test/Vectors/NPQCR3/sphincs-shake256-192s-robust.rsp";
			const std::string SPHINCSPLUS256F = "../../Test/Vectors/NPQCR3/sphincs-shake256-256f-robust.rsp";
			const std::string SPHINCSPLUS256S = "../../Test/Vectors/NPQCR3/sphincs-shake256-256s-robust.rsp";
		}
	}
}

#endif
