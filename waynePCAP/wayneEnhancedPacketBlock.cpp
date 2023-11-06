/*
 * wayneEnhancedPacketBlock.cpp
 *
 *  Created on: 2023年11月5日
 *      Author: weich
 */

#include "wayneEnhancedPacketBlock.hpp"

namespace wayne {
	namespace PCAP {

		EnhancedPacketBlock::EnhancedPacketBlock() {
			setBlockType(blockTypes::ENHANCED_PACKET);
			setInterfaceId((unsigned int)0);
			setTimestamp((unsigned long long)0);
			setPacketData("", 0, 0);

			updateBlockLength(structByteLength::EPB_INTERFACE_ID_LENGTH);
			updateBlockLength(structByteLength::EPB_TIMESTAMP_FULL_LENGTH);
			updateBlockLength(structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH);
			updateBlockLength(structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH);
		}

		EnhancedPacketBlock::EnhancedPacketBlock(unsigned int initInterfaceId, unsigned long long initTimestamp, unsigned int initCapturedPacketLength, unsigned int initOriginalPacketLength, char* packetData) {
			setBlockType(blockTypes::ENHANCED_PACKET);
			setInterfaceId(initInterfaceId);
			setTimestamp(initTimestamp);
			setPacketData(packetData, initCapturedPacketLength, initOriginalPacketLength);

			updateBlockLength(structByteLength::EPB_INTERFACE_ID_LENGTH);
			updateBlockLength(structByteLength::EPB_TIMESTAMP_FULL_LENGTH);
			updateBlockLength(structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH);
			updateBlockLength(structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH);
			updateBlockLength(wayne::numberUtil::nextNearestMultOfXFromY(initCapturedPacketLength, (unsigned int)structByteLength::BLOCK_READ_UNIT));
		}

		EnhancedPacketBlock::~EnhancedPacketBlock() {
			delete[] this->interfaceId;
			delete[] this->timestampLower;
			delete[] this->timestampUpper;
			delete[] this->capturedPacketLength;
			delete[] this->originalPacketLength;
			delete[] this->packetData;
			for (auto const& [key, option] : this->options)
			{
				delete[] option;
			}
			this->options.clear();
		}

		EnhancedPacketBlock::EnhancedPacketBlock(const EnhancedPacketBlock &other) {
			setInterfaceIdExact(other.interfaceId);
			setTimestampUpperExact(other.timestampUpper);
			setTimestampLowerExact(other.timestampLower);
			setPacketData(other.packetData, wayne::numberUtil::bytesStaticToNumber(other.capturedPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER), wayne::numberUtil::bytesStaticToNumber(other.originalPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER));
			for (auto const& [key, option] : other.options)
			{

			}
		}

		EnhancedPacketBlock::EnhancedPacketBlock(EnhancedPacketBlock &&other) {
			// TODO Auto-generated constructor stub

		}

		EnhancedPacketBlock& EnhancedPacketBlock::operator=(
				const EnhancedPacketBlock &other) {
			// TODO Auto-generated method stub

		}

		EnhancedPacketBlock& EnhancedPacketBlock::operator=(
				EnhancedPacketBlock &&other) {
			// TODO Auto-generated method stub

		}

		unsigned int EnhancedPacketBlock::getInterfaceId()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->interfaceId, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER);
		}

		char* EnhancedPacketBlock::getInterfaceIdExact()
		{
			char* toReturn = new char[structByteLength::EPB_INTERFACE_ID_LENGTH];
			std::copy(this->interfaceId, this->interfaceId + structByteLength::EPB_INTERFACE_ID_LENGTH, toReturn);
			return toReturn;
		}

		void EnhancedPacketBlock::setInterfaceId(unsigned int newInterfaceId)
		{
			delete[] this->interfaceId;
			this->interfaceId = wayne::numberUtil::numberToBytesStatic(newInterfaceId);
		}

		void EnhancedPacketBlock::setInterfaceIdExact(char* newInterfaceIdExact)
		{
			delete[] this->interfaceId;
			this->interfaceId = new char[structByteLength::EPB_INTERFACE_ID_LENGTH];
			std::copy(newInterfaceIdExact, newInterfaceIdExact + structByteLength::EPB_INTERFACE_ID_LENGTH, this->interfaceId);
		}

		unsigned long long EnhancedPacketBlock::getTimestamp()
		{
			char* fullTimeStamp = getTimestampExact();
			unsigned long long toReturn = wayne::numberUtil::bytesStaticToNumber(fullTimeStamp, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_LONG_LONG);
			delete[] fullTimeStamp;
			return toReturn;
		}

		char* EnhancedPacketBlock::getTimestampExact()
		{
			char* fullTimeStamp = new char[structByteLength::EPB_TIMESTAMP_FULL_LENGTH];
			std::copy(this->timestampUpper, this->timestampUpper + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, fullTimeStamp);
			std::copy(this->timestampLower, this->timestampLower + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, fullTimeStamp + 4);
			return fullTimeStamp;
		}

		unsigned int EnhancedPacketBlock::getTimestampUpper()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->timestampUpper, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER);
		}

		char* EnhancedPacketBlock::getTimestampUpperExact()
		{
			char* toReturn = new char[structByteLength::EPB_TIMESTAMP_UPPER_LENGTH];
			std::copy(this->timestampUpper, this->timestampUpper + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, toReturn);
			return toReturn;
		}

		unsigned int EnhancedPacketBlock::getTimestampLower()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->timestampLower, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER);
		}

		char* EnhancedPacketBlock::getTimestampLowerExact()
		{
			char* toReturn = new char[structByteLength::EPB_TIMESTAMP_LOWER_LENGTH];
			std::copy(this->timestampLower, this->timestampLower + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, toReturn);
			return toReturn;
		}

		void EnhancedPacketBlock::setTimestamp(unsigned long long newTimestamp)
		{
			delete[] this->timestampLower;
			delete[] this->timestampUpper;
			char* newTimestampExact = wayne::numberUtil::numberToBytesStatic(newTimestamp);
			this->timestampLower = new char[structByteLength::EPB_TIMESTAMP_LOWER_LENGTH];
			this->timestampUpper = new char[structByteLength::EPB_TIMESTAMP_UPPER_LENGTH];
			std::copy(newTimestampExact, newTimestampExact + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, this->timestampUpper);
			std::copy(newTimestampExact + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, newTimestampExact + structByteLength::EPB_TIMESTAMP_FULL_LENGTH, this->timestampLower);
			delete[] newTimestampExact;
		}

		void EnhancedPacketBlock::setTimestampExact(const char* newTimestampExact)
		{
			delete[] this->timestampLower;
			delete[] this->timestampUpper;
			this->timestampLower = new char[structByteLength::EPB_TIMESTAMP_LOWER_LENGTH];
			this->timestampUpper = new char[structByteLength::EPB_TIMESTAMP_UPPER_LENGTH];
			std::copy(newTimestampExact, newTimestampExact + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, this->timestampUpper);
			std::copy(newTimestampExact + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, newTimestampExact + structByteLength::EPB_TIMESTAMP_FULL_LENGTH, this->timestampLower);	
		}

		void EnhancedPacketBlock::setTimestampUpper(unsigned int newTimestampUpper)
		{
			delete[] this->timestampUpper;
			this->timestampUpper = wayne::numberUtil::numberToBytesStatic(newTimestampUpper);
		}

		void EnhancedPacketBlock::setTimestampUpperExact(const char* newTimestampUpperExact)
		{
			delete[] this->timestampUpper;
			std::copy(newTimestampUpperExact, newTimestampUpperExact + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, this->timestampUpper);
		}

		void EnhancedPacketBlock::setTimestampLower(unsigned int newTimestampLower)
		{
			delete[] this->timestampLower;
			this->timestampLower = wayne::numberUtil::numberToBytesStatic(newTimestampLower);
		}

		void EnhancedPacketBlock::setTimestampLowerExact(char* newTimestampLowerExact)
		{
			delete[] this->timestampLower;
			std::copy(newTimestampLowerExact, newTimestampLowerExact + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, this->timestampLower);
		}

		unsigned int EnhancedPacketBlock::getCapturedPacketLength()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->capturedPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER);
		}

		char* EnhancedPacketBlock::getCapturedPacketLengthExact()
		{
			char* toReturn = new char[structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH];
			std::copy(this->capturedPacketLength, this->capturedPacketLength + structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH, toReturn);
			return toReturn;
		}

		void EnhancedPacketBlock::setCapturedPacketLength(unsigned int newCapturedPacketLength)
		{
			delete[] this->capturedPacketLength;
			this->capturedPacketLength = wayne::numberUtil::numberToBytesStatic(newCapturedPacketLength);
		}

		void EnhancedPacketBlock::setCapturedPacketLengthExact(char* newCapturedPacketLengthExact)
		{
			delete[] this->capturedPacketLength;
			this->capturedPacketLength = new char[structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH];
			std::copy(newCapturedPacketLengthExact, newCapturedPacketLengthExact + structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH, this->capturedPacketLength);
		}

		unsigned int EnhancedPacketBlock::getOriginalPacketLength()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->originalPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER);
		}

		char* EnhancedPacketBlock::getOriginalPacketLengthExact()
		{
			char* toReturn = new char[structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH];
			std::copy(this->originalPacketLength, this->originalPacketLength + structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH, toReturn);
			return toReturn;
		}

		void EnhancedPacketBlock::setOriginalPacketLength(unsigned int newOriginalPacketLength)
		{
			delete[] this->originalPacketLength;
			this->originalPacketLength = wayne::numberUtil::numberToBytesStatic(newOriginalPacketLength);
		}

		void EnhancedPacketBlock::setOriginalPacketLengthExact(char* newOriginalPacketLengthExact)
		{
			delete[] this->originalPacketLength;
			this->originalPacketLength  = new char[structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH];
			std::copy(newOriginalPacketLengthExact, newOriginalPacketLengthExact + structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH, this->originalPacketLength);
		}

		char* EnhancedPacketBlock::getPacketData()
		{
			char* toReturn = new char[wayne::numberUtil::bytesStaticToNumber(this->capturedPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER)];
			std::copy(this->packetData, this->packetData + wayne::numberUtil::bytesStaticToNumber(this->capturedPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER), toReturn);
			return toReturn;
		}

		void EnhancedPacketBlock::setPacketData(const char* newPacketData, unsigned int newCapturedPacketLength, unsigned int newOriginalPacketLength)
		{
			updateBlockLength(-(wayne::numberUtil::bytesStaticToNumber(this->capturedPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER)));
			delete[] this->packetData;
			delete[] this->capturedPacketLength;
			delete[] this->originalPacketLength;
			std::copy(newPacketData, newPacketData + newCapturedPacketLength, this->packetData);
			updateBlockLength(newCapturedPacketLength);
			this->capturedPacketLength = wayne::numberUtil::numberToBytesStatic(newCapturedPacketLength);
			this->originalPacketLength = wayne::numberUtil::numberToBytesStatic(newOriginalPacketLength);
		}

		optionTypes* EnhancedPacketBlock::getAllOptionKeys()
		{
			optionTypes* allKeys = new optionTypes[this->options.size()];
			int counter = 0;
			for (auto const& [key, option] : this->options)
			{
				allKeys[counter] = key;
				counter++;
			}
			return allKeys;
		}
		
		unsigned int EnhancedPacketBlock::getAllOptionCount()
		{
			return (unsigned int)this->options.size();
		}

		char* EnhancedPacketBlock::getOption(optionTypes option)
		{
			char* toReturn;
			if (isOptionExist(option))
			{
				if (isDynamicLengthOption(option))
				{
					toReturn = new char[std::strlen(this->options[option])];
					std::copy(this->options[option], this->options[option] + std::strlen(this->options[option]), toReturn);
					return toReturn;
				}
				else
				{
					switch(option)
					{
						case optionTypes::EPB_DROPCOUNT:
							toReturn = new char[optionByteLength::EPB_DROPCOUNT_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::EPB_DROPCOUNT_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::EPB_FLAGS:
							toReturn = new char[optionByteLength::EPB_FLAGS_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::EPB_FLAGS_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::EPB_PACKETID:
							toReturn = new char[optionByteLength::EPB_PACKETID_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::EPB_PACKETID_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::EPB_QUEUE:
							toReturn = new char[optionByteLength::EPB_QUEUE_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::EPB_QUEUE_LENGTH, toReturn);
							return toReturn;
							break;
						default:
							return toReturn;
							break;
					}
				}
			}
			else
			{
				return toReturn;
			}
		}

		bool EnhancedPacketBlock::setOption(optionTypes option, const char* value, unsigned int valueLength)
		{

		}

		bool EnhancedPacketBlock::isOptionExist(optionTypes option)
		{
			for (auto const& [key, value] : this->options)
			{
				if (key == option)
				{
					return true;
				}
			}
			return false;
		}

		bool EnhancedPacketBlock::isOptionAcceptable(optionTypes option)
		{
			switch (option)
			{
				case optionTypes::EPB_DROPCOUNT:
				case optionTypes::EPB_FLAGS:
				case optionTypes::EPB_HASH:
				case optionTypes::EPB_PACKETID:
				case optionTypes::EPB_QUEUE:
				case optionTypes::EPB_VERDICT:
					return true;
					break;
				default:
					return false;
					break;
			}
		}

		bool EnhancedPacketBlock::isDynamicLengthOption(optionTypes option)
		{
			switch(option)
			{
				case optionTypes::EPB_HASH:
				case optionTypes::EPB_VERDICT:
					return true;
					break;
				default:
					return false;
					break;
			}
		}

		bool EnhancedPacketBlock::isStaticLengthOption(optionTypes option)
		{
			switch(option)
			{
				case optionTypes::EPB_DROPCOUNT:
				case optionTypes::EPB_FLAGS:
				case optionTypes::EPB_PACKETID:
				case optionTypes::EPB_QUEUE:
					return true;
					break;
				default:
					return false;
					break;
			}
		}

	} /* namespace PCAP */
} /* namespace wayne */
