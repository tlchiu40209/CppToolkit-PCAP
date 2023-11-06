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
		char* interfaceId = nullptr;
		char* timestampUpper = nullptr;
		char* timestampLower = nullptr;
		char* capturedPacketLength = nullptr;	// This is the actual captured packet length;
		char* originalPacketLength = nullptr; // This is the network packet length, in which means that, headers and others should be included.
		char* packetData = nullptr;
		std::map<optionTypes, char*> options;
	public:
		EnhancedPacketBlock();
		EnhancedPacketBlock(unsigned int initInterfaceId, unsigned long long timestamp, unsigned int initCapturedPacketLength, unsigned int initOriginalPacketLength, char* packetData);
		virtual ~EnhancedPacketBlock();
		EnhancedPacketBlock(const EnhancedPacketBlock &other);
		EnhancedPacketBlock(EnhancedPacketBlock &&other);
		EnhancedPacketBlock& operator=(const EnhancedPacketBlock &other);
		EnhancedPacketBlock& operator=(EnhancedPacketBlock &&other);
		bool operator==(const EnhancedPacketBlock &other);

		unsigned int getInterfaceId();
		char* getInterfaceIdExact();
		void setInterfaceId(unsigned int newInterfaceId);
		void setInterfaceIdExact(char* newInterfaceIdExact);

		unsigned long long getTimestamp();
		char* getTimestampExact();
		unsigned int getTimestampUpper();
		char* getTimestampUpperExact();
		unsigned int getTimestampLower();
		char* getTimestampLowerExact();
		void setTimestamp(unsigned long long newTimestamp);
		void setTimestampExact(const char* newTimestampExact);
		void setTimestampUpper(unsigned int newTimestampUpper);
		void setTimestampUpperExact(const char* newTimestampUpperExact);
		void setTimestampLower(unsigned int newTimestampLower);
		void setTimestampLowerExact(char* newTimestampLowerExact);

		unsigned int getCapturedPacketLength();
		char* getCapturedPacketLengthExact();
		void setCapturedPacketLength(unsigned int newCapturedPacketLength);
		void setCapturedPacketLengthExact(char* newCapturedPacketLengthExact);

		unsigned int getOriginalPacketLength();
		char* getOriginalPacketLengthExact();
		void setOriginalPacketLength(unsigned int newOriginalPacketLength);
		void setOriginalPacketLengthExact(char* newOriginalPacketLengthExact);

		char* getPacketData();
		void setPacketData(const char* newPacketData, unsigned int newCapturedPacketLength, unsigned int newOriginalPacketLength);

		optionTypes* getAllOptionKeys();
		unsigned int getAllOptionCount();
		char* getOption(optionTypes option);
		bool setOption(optionTypes option, const char* value, unsigned int valueLength);
		bool isOptionExist(optionTypes option);
		
		bool isOptionAcceptable(optionTypes option);
		bool isDynamicLengthOption(optionTypes option);
		bool isStaticLengthOption(optionTypes option);
	};

	} /* namespace PCAP */
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEENHANCEDPACKETBLOCK_HPP_ */
