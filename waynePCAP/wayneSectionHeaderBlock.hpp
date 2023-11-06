/*
 * wayneSectionHeaderBlock.hpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNESECTIONHEADERBLOCK_HPP_
#define LIB_WAYNEPCAP_WAYNESECTIONHEADERBLOCK_HPP_

#include "wayneBlock.hpp"
#include "wayneNumberUtil.hpp"
#include <map>

namespace wayne {
	namespace PCAP {
		class sectionHeaderBlock: protected block {
			protected:
				char* byteOrder = nullptr;		/*32 Bits*/
				char* majorVersion = nullptr;	/*16 Bits*/
				char* minorVersion = nullptr;	/*16 Bits*/
				char* sectionLength = nullptr;	/*64 Bits, -1 if the section length is not specified */
				std::map<optionTypes, char*> options; // @suppress("Invalid template argument")
			public:
				sectionHeaderBlock();
				sectionHeaderBlock(endianTypes initByteOrder);
				sectionHeaderBlock(endianTypes initByteOrder, short initMajorVersion, short initMinorVersion);
				virtual ~sectionHeaderBlock();
				sectionHeaderBlock(const sectionHeaderBlock &other);
				sectionHeaderBlock(sectionHeaderBlock &&other);
				sectionHeaderBlock& operator=(const sectionHeaderBlock &other);
				sectionHeaderBlock& operator=(sectionHeaderBlock &&other);
				bool operator==(const sectionHeaderBlock &other);

				endianTypes getByteOrder();
				char* getByteOrderExact();

				short getMajorVersion();
				char* getMajorVersionExact();
				void setMajorVersion(unsigned short newMajorVersion);
				void setMajorVersionExact(const char* newMajorVersion);

				short getMinorVersion();
				char* getMinorVersionExact();
				void setMinorVersion(unsigned short newMinorVersion);
				void setMinorVersionExact(const char* newMinorVersion);

				long getSectionLength();
				char* getSectionLengthExact();
				bool updateSectionLength(long deltaLength);
				bool updateSectionLengthExact(const char* deltaLengthExact);
				void setSectionLength(unsigned long exactLength);
				void setSectionLengthExact(const char* exactLengthExact);

				optionTypes* getAllOptionsKeys();
				int getAllOptionsCount();
				bool isOptionExist(optionTypes option);

				char* getOption(optionTypes option);
				//std::string getOptionString(optionTypes option);
				//unsigned short getOptionLength(optionTypes option);
				bool setOption(optionTypes option, const char* value, unsigned int valueLength);
				//bool setOptionString(optionTypes option, std::string value);

				bool isOptionAcceptable(optionTypes option);
				bool isDynamicLengthOption(optionTypes option);
				bool isStaticLengthOption(optionTypes option);
		};
	} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNESECTIONHEADERBLOCK_HPP_ */
