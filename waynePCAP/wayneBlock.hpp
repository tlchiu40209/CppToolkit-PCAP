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
				char* blockType;
				char* blockLength;

				void setBlockType(char* newBlockType);
				void setBlockType(blockTypes type);
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

				blockTypes getBlockType();
				char* getBlockTypeExact();

				int getBlockLength();
				char* getBlockLengthExact();
				//int getBlockLengthWithPadding(); /*The reason why it should be here is due to that reading PCAP is 4 bytes each read.*/
				//char* getBlockLengthWithPaddingExact();

		};
	} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEBLOCK_HPP_ */
