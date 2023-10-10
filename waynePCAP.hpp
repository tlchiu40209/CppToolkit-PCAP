/*
 * waynePCAP.hpp
 *
 *  Created on: 2023年10月7日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_HPP_
#define LIB_WAYNEPCAP_HPP_
#include <map>
#include <string>
#include <cstring>
#include <vector>

namespace wayne
{
	namespace PCAP
	{
		class PCAPNG
		{
			public:
				PCAPNG();
				PCAPNG(const PCAPNG &other);
				PCAPNG(PCAPNG &&other);
				virtual ~PCAPNG();
				PCAPNG& operator=(const PCAPNG &other);
				PCAPNG& operator=(PCAPNG &other);
				PCAPNG& operator==(const PCAPNG &other);
				PCAPNG& operator==(PCAPNG &other);
			private:

		};

	}
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_HPP_ */
