/*
 * wayneEnhancedPacketBlock.cpp
 *
 *  Created on: 2023年11月5日
 *      Author: weich
 */

#include "wayneEnhancedPacketBlock.hpp"

namespace wayne {
	namespace PCAP {

		enhancedPacketBlock::enhancedPacketBlock() 
		{
			setBlockType(blockTypes::ENHANCED_PACKET);
			setInterfaceId((unsigned int)0);
			setTimestamp((unsigned long long)0);
			setPacketData("", 0, 0);

			updateBlockLength(structByteLength::EPB_INTERFACE_ID_LENGTH);
			updateBlockLength(structByteLength::EPB_TIMESTAMP_FULL_LENGTH);
			updateBlockLength(structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH);
			updateBlockLength(structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH);
		}

		enhancedPacketBlock::enhancedPacketBlock(unsigned int initInterfaceId, unsigned long long initTimestamp, unsigned int initCapturedPacketLength, unsigned int initOriginalPacketLength, char* packetData) 
		{
			setBlockType(blockTypes::ENHANCED_PACKET);
			setInterfaceId(initInterfaceId);
			setTimestamp(initTimestamp);
			setPacketData(packetData, initCapturedPacketLength, initOriginalPacketLength);

			updateBlockLength(structByteLength::EPB_INTERFACE_ID_LENGTH);
			updateBlockLength(structByteLength::EPB_TIMESTAMP_FULL_LENGTH);
			updateBlockLength(structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH);
			updateBlockLength(structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH);
			updateBlockLength(numberUtil::nextNearestMultOfXFromY(initCapturedPacketLength, (unsigned int)structByteLength::BLOCK_READ_UNIT));
		}

		enhancedPacketBlock::~enhancedPacketBlock() 
		{
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

		enhancedPacketBlock::enhancedPacketBlock(const enhancedPacketBlock &other) 
		{
			setInterfaceIdExact(other.interfaceId);
			setTimestampUpperExact(other.timestampUpper);
			setTimestampLowerExact(other.timestampLower);
			setPacketData(other.packetData, numberUtil::bytesStaticToNumber(other.capturedPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT), numberUtil::bytesStaticToNumber(other.originalPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT));
			for (auto const& [key, option] : other.options)
			{
				int optionLength;
				if (isDynamicLengthOption(key))
				{
					optionLength = std::strlen(option);
				}
				else
				{
					switch(key)
					{
						case optionTypes::EPB_DROPCOUNT:
							optionLength = optionByteLength::EPB_DROPCOUNT_LENGTH;
							break;
						case optionTypes::EPB_FLAGS:
							optionLength = optionByteLength::EPB_FLAGS_LENGTH;
							break;
						case optionTypes::EPB_PACKETID:
							optionLength = optionByteLength::EPB_PACKETID_LENGTH;
							break;
						case optionTypes::EPB_QUEUE:
							default:
							break;
					}
				}
				this->options[key] = new char[optionLength];
				std::copy(option, option + optionLength, this->options[key]);
			}
		}

		enhancedPacketBlock::enhancedPacketBlock(enhancedPacketBlock &&other) 
		{
			this->interfaceId = other.interfaceId;
			this->timestampLower = other.timestampLower;
			this->timestampUpper = other.timestampUpper;
			this->capturedPacketLength = other.capturedPacketLength;
			this->originalPacketLength = other.originalPacketLength;
			this->packetData = other.packetData;

			other.interfaceId = nullptr;
			other.timestampLower = nullptr;
			other.timestampUpper = nullptr;
			other.capturedPacketLength = nullptr;
			other.originalPacketLength = nullptr;
			other.packetData = nullptr;

			for (auto const& [key, option] : other.options)
			{
				this->options[key] = option;
				other.options[key] = nullptr;
			}
		}

		enhancedPacketBlock& enhancedPacketBlock::operator=(const enhancedPacketBlock &other) {
			if (this != &other)
			{
				setInterfaceIdExact(other.interfaceId);
				setTimestampUpperExact(other.timestampUpper);
				setTimestampLowerExact(other.timestampLower);
				setPacketData(other.packetData, numberUtil::bytesStaticToNumber(other.capturedPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT), numberUtil::bytesStaticToNumber(other.originalPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT));
				for (auto const& [key, option] : other.options)
				{
					int optionLength;
					if (isDynamicLengthOption(key))
					{
						optionLength = std::strlen(option);
					}
					else
					{
						switch(key)
						{
							case optionTypes::EPB_DROPCOUNT:
								optionLength = optionByteLength::EPB_DROPCOUNT_LENGTH;
								break;
							case optionTypes::EPB_FLAGS:
								optionLength = optionByteLength::EPB_FLAGS_LENGTH;
								break;
							case optionTypes::EPB_PACKETID:
								optionLength = optionByteLength::EPB_PACKETID_LENGTH;
								break;
							case optionTypes::EPB_QUEUE:
								default:
								break;
						}
					}
					this->options[key] = new char[optionLength];
					std::copy(option, option + optionLength, this->options[key]);
				}
			}
			return *this;
		}

		enhancedPacketBlock& enhancedPacketBlock::operator=(enhancedPacketBlock &&other) {
			if (this != &other)
			{
				this->interfaceId = other.interfaceId;
				this->timestampLower = other.timestampLower;
				this->timestampUpper = other.timestampUpper;
				this->capturedPacketLength = other.capturedPacketLength;
				this->originalPacketLength = other.originalPacketLength;
				this->packetData = other.packetData;

				other.interfaceId = nullptr;
				other.timestampLower = nullptr;
				other.timestampUpper = nullptr;
				other.capturedPacketLength = nullptr;
				other.originalPacketLength = nullptr;
				other.packetData = nullptr;

				for (auto const& [key, option] : other.options)
				{
					this->options[key] = option;
					other.options[key] = nullptr;
				}
			}
			return *this;
		}

		bool enhancedPacketBlock::operator==(const enhancedPacketBlock &other)
		{
			if (numberUtil::bytesStaticToNumber(this->interfaceId, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != (numberUtil::bytesStaticToNumber(other.interfaceId, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)))
			{
				return false;
			}
			if (numberUtil::bytesStaticToNumber(this->timestampLower, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != (numberUtil::bytesStaticToNumber(other.timestampLower, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)))
			{
				return false;
			}
			if (numberUtil::bytesStaticToNumber(this->timestampUpper, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != (numberUtil::bytesStaticToNumber(other.timestampUpper, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)))
			{
				return false;
			}
			if (numberUtil::bytesStaticToNumber(this->capturedPacketLength, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != (numberUtil::bytesStaticToNumber(other.capturedPacketLength, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)))
			{
				return false;
			}
			if (numberUtil::bytesStaticToNumber(this->originalPacketLength, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != (numberUtil::bytesStaticToNumber(other.originalPacketLength, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)))
			{
				return false;
			}
			if (std::strcmp(this->packetData, other.packetData) != 0)
			{
				return false;
			}
			for (auto const& [key, option] : other.options)
			{
				if (std::strcmp(option, this->options[key]) != 0)
				{
					return false;
				}
			}
			return true;
		}

		unsigned int enhancedPacketBlock::getInterfaceId()
		{
			return numberUtil::bytesStaticToNumber(this->interfaceId, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		char* enhancedPacketBlock::getInterfaceIdExact()
		{
			char* toReturn = new char[structByteLength::EPB_INTERFACE_ID_LENGTH];
			std::copy(this->interfaceId, this->interfaceId + structByteLength::EPB_INTERFACE_ID_LENGTH, toReturn);
			return toReturn;
		}

		void enhancedPacketBlock::setInterfaceId(unsigned int newInterfaceId)
		{
			delete[] this->interfaceId;
			this->interfaceId = numberUtil::numberToBytesStatic(newInterfaceId, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		void enhancedPacketBlock::setInterfaceIdExact(char* newInterfaceIdExact)
		{
			delete[] this->interfaceId;
			this->interfaceId = new char[structByteLength::EPB_INTERFACE_ID_LENGTH];
			std::copy(newInterfaceIdExact, newInterfaceIdExact + structByteLength::EPB_INTERFACE_ID_LENGTH, this->interfaceId);
		}

		unsigned long long enhancedPacketBlock::getTimestamp()
		{
			char* fullTimeStamp = getTimestampExact();
			unsigned long long toReturn = numberUtil::bytesStaticToNumber(fullTimeStamp, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_LONG_LONG, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
			delete[] fullTimeStamp;
			return toReturn;
		}

		char* enhancedPacketBlock::getTimestampExact()
		{
			char* fullTimeStamp = new char[structByteLength::EPB_TIMESTAMP_FULL_LENGTH];
			std::copy(this->timestampUpper, this->timestampUpper + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, fullTimeStamp);
			std::copy(this->timestampLower, this->timestampLower + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, fullTimeStamp + 4);
			return fullTimeStamp;
		}

		unsigned int enhancedPacketBlock::getTimestampUpper()
		{
			return numberUtil::bytesStaticToNumber(this->timestampUpper, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		char* enhancedPacketBlock::getTimestampUpperExact()
		{
			char* toReturn = new char[structByteLength::EPB_TIMESTAMP_UPPER_LENGTH];
			std::copy(this->timestampUpper, this->timestampUpper + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, toReturn);
			return toReturn;
		}

		unsigned int enhancedPacketBlock::getTimestampLower()
		{
			return numberUtil::bytesStaticToNumber(this->timestampLower, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		char* enhancedPacketBlock::getTimestampLowerExact()
		{
			char* toReturn = new char[structByteLength::EPB_TIMESTAMP_LOWER_LENGTH];
			std::copy(this->timestampLower, this->timestampLower + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, toReturn);
			return toReturn;
		}

		void enhancedPacketBlock::setTimestamp(unsigned long long newTimestamp)
		{
			delete[] this->timestampLower;
			delete[] this->timestampUpper;
			char* newTimestampExact = numberUtil::numberToBytesStatic(newTimestamp, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
			this->timestampLower = new char[structByteLength::EPB_TIMESTAMP_LOWER_LENGTH];
			this->timestampUpper = new char[structByteLength::EPB_TIMESTAMP_UPPER_LENGTH];
			std::copy(newTimestampExact, newTimestampExact + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, this->timestampUpper);
			std::copy(newTimestampExact + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, newTimestampExact + structByteLength::EPB_TIMESTAMP_FULL_LENGTH, this->timestampLower);
			delete[] newTimestampExact;
		}

		void enhancedPacketBlock::setTimestampExact(const char* newTimestampExact)
		{
			delete[] this->timestampLower;
			delete[] this->timestampUpper;
			this->timestampLower = new char[structByteLength::EPB_TIMESTAMP_LOWER_LENGTH];
			this->timestampUpper = new char[structByteLength::EPB_TIMESTAMP_UPPER_LENGTH];
			std::copy(newTimestampExact, newTimestampExact + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, this->timestampUpper);
			std::copy(newTimestampExact + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, newTimestampExact + structByteLength::EPB_TIMESTAMP_FULL_LENGTH, this->timestampLower);	
		}

		void enhancedPacketBlock::setTimestampUpper(unsigned int newTimestampUpper)
		{
			delete[] this->timestampUpper;
			this->timestampUpper = numberUtil::numberToBytesStatic(newTimestampUpper, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		void enhancedPacketBlock::setTimestampUpperExact(const char* newTimestampUpperExact)
		{
			delete[] this->timestampUpper;
			std::copy(newTimestampUpperExact, newTimestampUpperExact + structByteLength::EPB_TIMESTAMP_UPPER_LENGTH, this->timestampUpper);
		}

		void enhancedPacketBlock::setTimestampLower(unsigned int newTimestampLower)
		{
			delete[] this->timestampLower;
			this->timestampLower = numberUtil::numberToBytesStatic(newTimestampLower, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		void enhancedPacketBlock::setTimestampLowerExact(char* newTimestampLowerExact)
		{
			delete[] this->timestampLower;
			std::copy(newTimestampLowerExact, newTimestampLowerExact + structByteLength::EPB_TIMESTAMP_LOWER_LENGTH, this->timestampLower);
		}

		unsigned int enhancedPacketBlock::getCapturedPacketLength()
		{
			return numberUtil::bytesStaticToNumber(this->capturedPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		char* enhancedPacketBlock::getCapturedPacketLengthExact()
		{
			char* toReturn = new char[structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH];
			std::copy(this->capturedPacketLength, this->capturedPacketLength + structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH, toReturn);
			return toReturn;
		}

		void enhancedPacketBlock::setCapturedPacketLength(unsigned int newCapturedPacketLength)
		{
			delete[] this->capturedPacketLength;
			this->capturedPacketLength = numberUtil::numberToBytesStatic(newCapturedPacketLength, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		void enhancedPacketBlock::setCapturedPacketLengthExact(char* newCapturedPacketLengthExact)
		{
			delete[] this->capturedPacketLength;
			this->capturedPacketLength = new char[structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH];
			std::copy(newCapturedPacketLengthExact, newCapturedPacketLengthExact + structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH, this->capturedPacketLength);
		}

		unsigned int enhancedPacketBlock::getOriginalPacketLength()
		{
			return numberUtil::bytesStaticToNumber(this->originalPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		char* enhancedPacketBlock::getOriginalPacketLengthExact()
		{
			char* toReturn = new char[structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH];
			std::copy(this->originalPacketLength, this->originalPacketLength + structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH, toReturn);
			return toReturn;
		}

		void enhancedPacketBlock::setOriginalPacketLength(unsigned int newOriginalPacketLength)
		{
			delete[] this->originalPacketLength;
			this->originalPacketLength = numberUtil::numberToBytesStatic(newOriginalPacketLength, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		void enhancedPacketBlock::setOriginalPacketLengthExact(char* newOriginalPacketLengthExact)
		{
			delete[] this->originalPacketLength;
			this->originalPacketLength  = new char[structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH];
			std::copy(newOriginalPacketLengthExact, newOriginalPacketLengthExact + structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH, this->originalPacketLength);
		}

		char* enhancedPacketBlock::getPacketData()
		{
			char* toReturn = new char[numberUtil::bytesStaticToNumber(this->capturedPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)];
			std::copy(this->packetData, this->packetData + numberUtil::bytesStaticToNumber(this->capturedPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT), toReturn);
			return toReturn;
		}

		void enhancedPacketBlock::setPacketData(const char* newPacketData, unsigned int newCapturedPacketLength, unsigned int newOriginalPacketLength)
		{
			updateBlockLength(-(numberUtil::bytesStaticToNumber(this->capturedPacketLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)));
			delete[] this->packetData;
			delete[] this->capturedPacketLength;
			delete[] this->originalPacketLength;
			std::copy(newPacketData, newPacketData + newCapturedPacketLength, this->packetData);
			updateBlockLength(newCapturedPacketLength);
			this->capturedPacketLength = numberUtil::numberToBytesStatic(newCapturedPacketLength, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
			this->originalPacketLength = numberUtil::numberToBytesStatic(newOriginalPacketLength, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		optionTypes* enhancedPacketBlock::getAllOptionKeys()
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
		
		unsigned int enhancedPacketBlock::getAllOptionCount()
		{
			return (unsigned int)this->options.size();
		}

		char* enhancedPacketBlock::getOption(optionTypes option)
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

		bool enhancedPacketBlock::setOption(optionTypes option, const char* value, unsigned int valueLength)
		{
			if (isOptionAcceptable(option))
			{
				/* Handling the length request. */
				if (isOptionExist(option))
				{
					if (isDynamicLengthOption(option))
					{
						int recoveredLength = std::strlen(this->options[option]);
						updateBlockLength(-recoveredLength);
						updateBlockLength(valueLength);
					}
				}
				else
				{
					if (isDynamicLengthOption(option))
					{
						updateBlockLength((int)4 + numberUtil::nextNearestMultOfXFromY((int)valueLength, (int)structByteLength::BLOCK_READ_UNIT));
					}
					else
					{
						switch (option)
						{
							case optionTypes::EPB_DROPCOUNT:
								if (valueLength != optionByteLength::EPB_DROPCOUNT_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::EPB_DROPCOUNT_LENGTH);
								break;
							case optionTypes::EPB_FLAGS:
								if (valueLength != optionByteLength::EPB_FLAGS_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::EPB_FLAGS_LENGTH);
								break;
							case optionTypes::EPB_PACKETID:
								if (valueLength != optionByteLength::EPB_PACKETID_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::EPB_PACKETID_LENGTH);
								break;
							case optionTypes::EPB_QUEUE:
								if (valueLength != optionByteLength::EPB_QUEUE_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::EPB_QUEUE_LENGTH);
								break;
							default:
								return false;
								break;
						}
					}
				}
				/* End of handling the length request */

				if (isOptionExist(option))
				{
					delete[] this->options[option];
				}
				char* newOption = new char[valueLength];
				std::copy(value, value + valueLength, newOption);
				this->options[option] = newOption;
				return true;
			}
			else
			{
				return false;
			}
		}

		bool enhancedPacketBlock::isOptionExist(optionTypes option)
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

		bool enhancedPacketBlock::isOptionAcceptable(optionTypes option)
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

		bool enhancedPacketBlock::isDynamicLengthOption(optionTypes option)
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

		bool enhancedPacketBlock::isStaticLengthOption(optionTypes option)
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
