/*
 * wayneEnhancedPacketBlock.hpp
 *
 *  Created on: 2023年11月5日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNEENHANCEDPACKETBLOCK_HPP_
#define LIB_WAYNEPCAP_WAYNEENHANCEDPACKETBLOCK_HPP_

#include "wayneBlock.hpp"

namespace wayne {
namespace PCAP {

class EnhancedPacketBlock: public block {
protected:
	char* interfaceId;
	char* timestampUpper;
	char* timestampLower;
	char* capturedPacketLength;	// This is the actual captured packet length;
	char* originalPacketLength; // This is the network packet length, in which means that, headers and others should be included.
	char* packetData;
	std::map<optionTypes, char*> options;
public:
	EnhancedPacketBlock();
	EnhancedPacketBlock(unsigned int initInterfaceId, unsigned int initTimestampUpper, unsigned int initTimestampLower, unsigned int initCapturedPacketLength, unsigned int initOriginalPacketLength, char* packetData);
	virtual ~EnhancedPacketBlock();
	EnhancedPacketBlock(const EnhancedPacketBlock &other);
	EnhancedPacketBlock(EnhancedPacketBlock &&other);
	EnhancedPacketBlock& operator=(const EnhancedPacketBlock &other);
	EnhancedPacketBlock& operator=(EnhancedPacketBlock &&other);

	unsigned int getInterfaceId();
	char* getInterfaceIdExact();
	void setInterfaceId(unsigned int newInterfaceId);
	void setInterfaceIdExact(char* newInterfaceId);

	unsigned long long getTimestamp();
	char* getTimestampExact();
	unsigned int getTimestampUpper();
	char* getTimestampUpperExact();
	unsigned int getTimestampLower();
	char* getTimestampLowerExact();
	void setTimestamp(unsigned long long newTimestamp);
	void setTimestampExact(char* newTimestampExact);
	void setTimestampUpper(unsigned int newTimestampUpper);
	void setTimestampUpperExact(char* newTimestampUpperExact);
	void setTimestampLower(unsigned int newTimestampLower);
	void setTimestampLowerExact(char* newTimestampLowerExact);

	unsigned int getCapturedPacketLength();
	char* getCapturedPacketLengthExact();
	void setCapturedPacketLength(unsigned int newCapturedPacketLength);
	void setCapturedPacketLengthExact(char* newCapturedPacketLengthExact);

	unsigned int getOriginalPacketLength();
	char* getOriginalPacketLengthExact();
	void setOriginalPacketLength(unsigned int newOriginalPacketLength);
	void setOriginalPacketLengthExact(unsigned int newOriginalPacketLengthExact);
};

} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEENHANCEDPACKETBLOCK_HPP_ */
