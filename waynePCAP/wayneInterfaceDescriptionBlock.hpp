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
		char* linkType;	/*16 Bits*/
		char* reserved;	/*16 Bits, always 0x0, 0x0*/
		char* snapLength;	/*32 bits*/
		std::map<optionTypes, char*> options; // @suppress("Invalid template argument")
	public:
		interfaceDescriptionBlock();
		interfaceDescriptionBlock(char* linkTypeExact);
		virtual ~interfaceDescriptionBlock();
		interfaceDescriptionBlock(const interfaceDescriptionBlock &other);
		interfaceDescriptionBlock(interfaceDescriptionBlock &&other);
		interfaceDescriptionBlock& operator=(
				const interfaceDescriptionBlock &other);
		interfaceDescriptionBlock& operator=(interfaceDescriptionBlock &&other);
	};

	} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEINTERFACEDESCRIPTIONBLOCK_HPP_ */
