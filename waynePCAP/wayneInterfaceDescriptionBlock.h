/*
 * wayneInterfaceDescriptionBlock.h
 *
 *  Created on: 2023年10月18日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNEINTERFACEDESCRIPTIONBLOCK_H_
#define LIB_WAYNEPCAP_WAYNEINTERFACEDESCRIPTIONBLOCK_H_

#include "wayneBlock.hpp"

namespace wayne {
namespace PCAP {

class interfaceDescriptionBlock: public block {
public:
	interfaceDescriptionBlock();
	virtual ~interfaceDescriptionBlock();
	interfaceDescriptionBlock(const interfaceDescriptionBlock &other);
	interfaceDescriptionBlock(interfaceDescriptionBlock &&other);
	interfaceDescriptionBlock& operator=(
			const interfaceDescriptionBlock &other);
	interfaceDescriptionBlock& operator=(interfaceDescriptionBlock &&other);
};

} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEINTERFACEDESCRIPTIONBLOCK_H_ */
