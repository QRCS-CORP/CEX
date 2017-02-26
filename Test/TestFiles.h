#ifndef _CEXTEST_TESTFILES_H
#define _CEXTEST_TESTFILES_H

#include <string>

namespace TestFiles
{
    namespace AESAVS 
	{
        const std::string AESAVSKEY128 = "Vectors/AESAVS/keyvect128.txt";
        const std::string AESAVSKEY192 = "Vectors/AESAVS/keyvect192.txt";
        const std::string AESAVSKEY256 = "Vectors/AESAVS/keyvect256.txt";
        const std::string AESAVSPTEXT128 = "Vectors/AESAVS/plainvect128.txt";
        const std::string AESAVSPTEXT192 = "Vectors/AESAVS/plainvect192.txt";
        const std::string AESAVSPTEXT256 = "Vectors/AESAVS/plainvect256.txt";
    }
    
	namespace Counterpane 
	{
		const std::string TWOFISHCTEXT128 = "Vectors/Counterpane/twofishcipher128.txt";
		const std::string TWOFISHCTEXT192 = "Vectors/Counterpane/twofishcipher192.txt";
		const std::string TWOFISHCTEXT256 = "Vectors/Counterpane/twofishcipher256.txt";
		const std::string TWOFISHKEY128 = "Vectors/Counterpane/twofishkey128.txt";
		const std::string TWOFISHKEY192 = "Vectors/Counterpane/twofishkey192.txt";
		const std::string TWOFISHKEY256 = "Vectors/Counterpane/twofishkey256.txt";
	}

    namespace Nessie 
	{
        const std::string SERPENTCTEXT128 = "Vectors/Nessie/serpentcipher128.txt";
        const std::string SERPENTCTEXT192 = "Vectors/Nessie/serpentcipher192.txt";
        const std::string SERPENTCTEXT256 = "Vectors/Nessie/serpentcipher256.txt";
        const std::string SERPENTKEY128 = "Vectors/Nessie/serpentkey128.txt";
        const std::string SERPENTKEY192 = "Vectors/Nessie/serpentkey192.txt";
        const std::string SERPENTKEY256 = "Vectors/Nessie/serpentkey256.txt";
        const std::string SERPENTM100X128 = "Vectors/Nessie/serpentmonte100-128.txt";
        const std::string SERPENTM100X192 = "Vectors/Nessie/serpentmonte100-192.txt";
        const std::string SERPENTM100X256 = "Vectors/Nessie/serpentmonte100-256.txt";
        const std::string SERPENTM1000X128 = "Vectors/Nessie/serpentmonte1000-128.txt";
        const std::string SERPENTM1000X192 = "Vectors/Nessie/serpentmonte1000-192.txt";
        const std::string SERPENTM1000X256 = "Vectors/Nessie/serpentmonte1000-256.txt";
        const std::string SERPENTPTEXT128 = "Vectors/Nessie/serpentplain128.txt";
        const std::string SERPENTPTEXT192 = "Vectors/Nessie/serpentplain192.txt";
        const std::string SERPENTPTEXT256 = "Vectors/Nessie/serpentplain256.txt";
    }
}

#endif
