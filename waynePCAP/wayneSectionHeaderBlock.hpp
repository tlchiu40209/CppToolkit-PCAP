/*
 * wayneSectionHeaderBlock.hpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNESECTIONHEADERBLOCK_HPP_
#define LIB_WAYNEPCAP_WAYNESECTIONHEADERBLOCK_HPP_

#include "wayneBlock.hpp"
#include <map>

namespace wayne {
	namespace PCAP {
		class sectionHeaderBlock: protected block {
			protected:
				char* byteOrder;		/*32 Bits*/
				char* majorVersion;	/*16 Bits*/
				char* minorVersion;	/*16 Bits*/
				char* sectionLength;	/*64 Bits, -1 if the section length is not specified */
				std::map<optionTypes, char*> options; // @suppress("Invalid template argument")
			public:
				sectionHeaderBlock();
				sectionHeaderBlock(endianTypes initByteOrder);
				sectionHeaderBlock(const char* initByteOrderExact);
				sectionHeaderBlock(endianTypes initByteOrder, size_t initMajorVersion, size_t initMinorVersion);
				sectionHeaderBlock(const char* initByteOrderExact, const char* initMajorVersionExact, const char* initMinorVersionExact);
				virtual ~sectionHeaderBlock();
				sectionHeaderBlock(const sectionHeaderBlock &other);
				sectionHeaderBlock(sectionHeaderBlock &&other);
				sectionHeaderBlock& operator=(const sectionHeaderBlock &other);
				sectionHeaderBlock& operator=(sectionHeaderBlock &&other);
				bool operator==(const sectionHeaderBlock &other);

				endianTypes getByteOrder();
				char* getByteOrderExact();

				size_t getMajorVersion();
				char* getMajorVersionExact();
				void setMajorVersion(size_t newMajorVersion);
				void setMajorVersionExact(const char* newMajorVersion);

				size_t getMinorVersion();
				char* getMinorVersionExact();
				void setMinorVersion(size_t newMinorVersion);
				void setMinorVersionExact(const char* newMinorVersion);

				size_t getSectionLength();
				char* getSectionLengthExact();
				bool updateSectionLength(size_t deltaLength, bool isPositive);
				bool updateSectionLengthExact(const char* unsignedDeltaLengthExact, bool isPositive);
				void setSectionLengthDirect(size_t exactLength);
				void setSectionLengthDirectExact(const char* unsignedExactLengthExact);

				optionTypes* getAllOptionsKeys();
				size_t getAllOptionsCount();
				bool isOptionExist(optionTypes option);

				char* getOption(optionTypes option);
				std::string getOptionString(optionTypes option);
				bool setOption(optionTypes option, const char* value);
				bool setOptionString(optionTypes option, std::string value);
				bool isOptionAcceptable(optionTypes option);
		};
	} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNESECTIONHEADERBLOCK_HPP_ */
