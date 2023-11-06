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
#include "wayneNumberUtil.hpp"

namespace wayne {
	namespace PCAP {
		class block {
			protected:
				char* blockType = nullptr;
				char* blockLength = nullptr;
				void setBlockType(blockTypes type);
				void setBlockTypeExact(char* newBlockType);
				bool updateBlockLength(int deltaLength);
				bool updateBlockLengthExact(const char* deltaLengthExact);
				void setBlockLength(unsigned int exactLength);
				void setBlockLengthExact(const char* exactLengthExact);
			public:
				block();
				block(blockTypes type);
				virtual ~block();
				block(const block &other);
				block(block &&other);
				block& operator=(const block &other);
				block& operator=(block &&other);
				bool operator==(const block &other);

				blockTypes getBlockType();
				char* getBlockTypeExact();

				int getBlockLength();
				char* getBlockLengthExact();
		};
	} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEBLOCK_HPP_ */
