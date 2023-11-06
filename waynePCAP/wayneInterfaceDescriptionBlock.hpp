/*
 * wayneInterfaceDescriptionBlock.h
 *
 *  Created on: 2023年10月18日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNEINTERFACEDESCRIPTIONBLOCK_HPP_
#define LIB_WAYNEPCAP_WAYNEINTERFACEDESCRIPTIONBLOCK_HPP_

#include "wayneBlock.hpp"
#include <map>

namespace wayne {
	namespace PCAP {

	class interfaceDescriptionBlock: public block {
	protected:
		char* linkType = nullptr;	/*16 Bits*/
		char* reserved = nullptr;	/*16 Bits, always 0x0, 0x0*/
		char* snapLength = nullptr;	/*32 bits*/
		std::map<optionTypes, char*> options;
		std::map<optionTypes, unsigned int> multCounts;
	public:
		interfaceDescriptionBlock();
		interfaceDescriptionBlock(linkTypes initType, unsigned int initSnapLength);
		virtual ~interfaceDescriptionBlock();
		interfaceDescriptionBlock(const interfaceDescriptionBlock &other);
		interfaceDescriptionBlock(interfaceDescriptionBlock &&other);
		interfaceDescriptionBlock& operator=(const interfaceDescriptionBlock &other);
		interfaceDescriptionBlock& operator=(interfaceDescriptionBlock &&other);

		linkTypes getLinkType();
		char* getLinkTypeExact();
		void setLinkType(linkTypes type);
		void setLinkTypeExact(const char* linkTypeExact);

		unsigned int getSnapLength();
		char* getSnapLengthExact();
		void setSnapLength(unsigned int newSnapLength);
		void setSnapLengthExact(const char* newSnapLengthExact);

		optionTypes* getAllOptionKeys();
		unsigned int getAllOptionsCount();
		char* getOption(optionTypes option);
		bool setOption(optionTypes option, const char* value, unsigned int valueLength);
		bool isOptionExist(optionTypes option);
		bool isOptionAcceptable(optionTypes option);
		bool isOptionCurrentlyMultiple(optionTypes option);
		unsigned int getCurrentMultipleOptionsMult(optionTypes option);

		bool isDynamicLengthOption(optionTypes option);
		bool isStaticLengthOption(optionTypes option);
		bool isStaticLengthOptionAllowsMultiple(optionTypes option);

	};

	} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEINTERFACEDESCRIPTIONBLOCK_HPP_ */
