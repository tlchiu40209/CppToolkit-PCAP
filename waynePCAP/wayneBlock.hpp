/*
 * wayneBlock.hpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNEBLOCK_HPP_
#define LIB_WAYNEPCAP_WAYNEBLOCK_HPP_
#include <string>
#include <cstring>
#include "wayneEnums.hpp"
#include "wayneByteSeqs.hpp"
#include "wayneIdentBytes.hpp"

namespace wayne {
	namespace PCAP {
		class block {
			protected:
				char* blockType;
				char* blockLength;

				void setBlockType(char* newBlockType);
				void setBlockType(blockTypes type);
			public:
				block();
				virtual ~block();
				block(const block &other);
				block(block &&other);
				block& operator=(const block &other);
				block& operator=(block &&other);

				blockTypes getBlockType();
				char* getBlockTypeExact();

				size_t getBlockLength();
				char* getBlockLengthExact();
		};
	} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEBLOCK_HPP_ */
