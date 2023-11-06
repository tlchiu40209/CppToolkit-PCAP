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
#include "wayneSectionHeaderBlock.hpp"
#include "wayneInterfaceDescriptionBlock.hpp"
#include "wayneEnhancedPacketBlock.hpp"

namespace wayne
{
	namespace PCAP
	{
		class PCAPNG
		{
			protected:
				sectionHeaderBlock sectionHeader;
				interfaceDescriptionBlock interfaceDescription;
				std::map<unsigned long long, enhancedPacketBlock> packets; // unsigned long long = timestamp, enhancedPacketBlock = packet
			public:
				PCAPNG();
				PCAPNG(const PCAPNG &other);
				PCAPNG(PCAPNG &&other);
				virtual ~PCAPNG();
				PCAPNG& operator=(const PCAPNG &other);
				PCAPNG& operator=(PCAPNG &&other);
				bool operator==(const PCAPNG &other);

				sectionHeaderBlock getSectionHeader();
				void setSectionHeader(sectionHeaderBlock newSectionHeader);
				interfaceDescriptionBlock getInterfaceDescriptionBlock();
				void setInterfaceDescriptionBlock(interfaceDescriptionBlock newInterfaceDescription);

		};

	}
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_HPP_ */
