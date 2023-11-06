/*
 * wayneSectionHeaderBlock.cpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#include "wayneSectionHeaderBlock.hpp"

namespace wayne {
	namespace PCAP {

		sectionHeaderBlock::sectionHeaderBlock()
		{
			setBlockType(blockTypes::SECTION_HEADER);
			this->byteOrder = new char[structByteLength::SHB_BYTE_ORDER_LENGTH];
			if (wayne::numberUtil::isBigEndian()) {
				std::copy(endianTypesBytes::ENDIAN_TYPE_BIG_BYTES, endianTypesBytes::ENDIAN_TYPE_BIG_BYTES + structByteLength::SHB_BYTE_ORDER_LENGTH, this->byteOrder);
			} else {
				std::copy(endianTypesBytes::ENDIAN_TYPE_SMALL_BYTES, endianTypesBytes::ENDIAN_TYPE_SMALL_BYTES + structByteLength::SHB_BYTE_ORDER_LENGTH, this->byteOrder);
			}
			setMajorVersion((unsigned short)structByteDefault::SHB_MAJOR_VERSION_VALUE);
			setMinorVersion((unsigned short)structByteDefault::SHB_MINOR_VERSION_VALUE);
			setSectionLength((unsigned long)structByteDefault::SHB_SECTION_LENGTH_VALUE);

			updateBlockLength(structByteLength::SHB_BYTE_ORDER_LENGTH);
			updateBlockLength(structByteLength::SHB_MAJOR_VERSION_LENGTH + structByteLength::SHB_MINOR_VERSION_LENGTH);
			updateBlockLength(structByteLength::SHB_SECTION_LENGTH_LENGTH);
		}

		sectionHeaderBlock::sectionHeaderBlock(endianTypes initByteOrder)
		{
			setBlockType(blockTypes::SECTION_HEADER);
			this->byteOrder = new char[structByteLength::SHB_BYTE_ORDER_LENGTH];
			switch (initByteOrder) {
			case endianTypes::ENDIAN_TYPE_BIG:
				std::copy(endianTypesBytes::ENDIAN_TYPE_BIG_BYTES, endianTypesBytes::ENDIAN_TYPE_BIG_BYTES + structByteLength::SHB_BYTE_ORDER_LENGTH, this->byteOrder);
				break;
			case endianTypes::ENDIAN_TYPE_SMALL:
				std::copy(endianTypesBytes::ENDIAN_TYPE_SMALL_BYTES, endianTypesBytes::ENDIAN_TYPE_SMALL_BYTES + structByteLength::SHB_BYTE_ORDER_LENGTH, this->byteOrder);
				break;
			}
			setMajorVersion((unsigned short)structByteDefault::SHB_MAJOR_VERSION_VALUE);
			setMinorVersion((unsigned short)structByteDefault::SHB_MINOR_VERSION_VALUE);
			setSectionLength((unsigned long)structByteDefault::SHB_SECTION_LENGTH_VALUE);

			updateBlockLength(structByteLength::SHB_BYTE_ORDER_LENGTH);
			updateBlockLength(structByteLength::SHB_MAJOR_VERSION_LENGTH + structByteLength::SHB_MINOR_VERSION_LENGTH);
			updateBlockLength(structByteLength::SHB_SECTION_LENGTH_LENGTH);
		}

		sectionHeaderBlock::sectionHeaderBlock(endianTypes initByteOrder, short initMajorVersion, short initMinorVersion)
		{
			setBlockType(blockTypes::SECTION_HEADER);
			this->byteOrder = new char[structByteLength::SHB_BYTE_ORDER_LENGTH];
			switch (initByteOrder) {
			case endianTypes::ENDIAN_TYPE_BIG:
				std::copy(endianTypesBytes::ENDIAN_TYPE_BIG_BYTES, endianTypesBytes::ENDIAN_TYPE_BIG_BYTES + structByteLength::SHB_BYTE_ORDER_LENGTH, this->byteOrder);
				break;
			case endianTypes::ENDIAN_TYPE_SMALL:
				std::copy(endianTypesBytes::ENDIAN_TYPE_SMALL_BYTES, endianTypesBytes::ENDIAN_TYPE_SMALL_BYTES + structByteLength::SHB_BYTE_ORDER_LENGTH, this->byteOrder);
				break;
			}
			setMajorVersion((unsigned short)initMajorVersion);
			setMinorVersion((unsigned short)initMinorVersion);
			setSectionLength((unsigned long)structByteDefault::SHB_SECTION_LENGTH_VALUE);

			updateBlockLength(structByteLength::SHB_BYTE_ORDER_LENGTH);
			updateBlockLength(structByteLength::SHB_MAJOR_VERSION_LENGTH + structByteLength::SHB_MINOR_VERSION_LENGTH);
			updateBlockLength(structByteLength::SHB_SECTION_LENGTH_LENGTH);
		}


		sectionHeaderBlock::~sectionHeaderBlock()
		{
			delete[] this->byteOrder;
			delete[] this->majorVersion;
			delete[] this->minorVersion;
			delete[] this->sectionLength;
			for (auto const& [key, option] : this->options) // @suppress("Symbol is not resolved")
			{
				delete[] option;
			}
			options.clear();
		}

		sectionHeaderBlock::sectionHeaderBlock(const sectionHeaderBlock &other)
		{
			delete[] this->byteOrder;
			this->byteOrder = new char[structByteLength::SHB_BYTE_ORDER_LENGTH];
			std::copy(other.byteOrder, other.byteOrder + structByteLength::SHB_BYTE_ORDER_LENGTH, this->byteOrder);
			setMajorVersionExact(other.majorVersion);
			setMinorVersionExact(other.minorVersion);
			setSectionLengthExact(other.sectionLength);
			for (auto const& [key, option] : other.options)
			{
				if (isDynamicLengthOption(key))
				{
					setOption(key, option, std::strlen(option));
				}
			}
		}

		sectionHeaderBlock::sectionHeaderBlock(sectionHeaderBlock &&other)
		{
			//block(other);
			this->byteOrder = other.byteOrder;
			this->majorVersion = other.majorVersion;
			this->minorVersion = other.minorVersion;
			this->sectionLength = other.sectionLength;
			for (auto const& [key, option] : other.options)
			{
				this->options[key] = option;
				other.options[key]=nullptr;
			}
			other.byteOrder = nullptr;
			other.majorVersion = nullptr;
			other.minorVersion = nullptr;
			other.sectionLength = nullptr;
			other.options.clear();
		}

		sectionHeaderBlock& sectionHeaderBlock::operator=(const sectionHeaderBlock &other)
		{
			if (this != &other)
			{
				delete[] this->byteOrder;
				this->byteOrder = new char[structByteLength::SHB_BYTE_ORDER_LENGTH];
				std::copy(other.byteOrder, other.byteOrder + structByteLength::SHB_BYTE_ORDER_LENGTH, this->byteOrder);
				setMajorVersionExact(other.majorVersion);
				setMinorVersionExact(other.minorVersion);
				setSectionLengthExact(other.sectionLength);
				for (auto const& [key, option] : other.options)
				{
					if (isDynamicLengthOption(key))
					{
						setOption(key, option, std::strlen(option));
					}
				}
			}
			return *this;
		}

		sectionHeaderBlock& sectionHeaderBlock::operator=(sectionHeaderBlock &&other)
		{
			if (this != &other)
			{
				this->byteOrder = other.byteOrder;
				this->majorVersion = other.majorVersion;
				this->minorVersion = other.minorVersion;
				this->sectionLength = other.sectionLength;
				for (auto const& [key, option] : other.options)
				{
					this->options[key] = option;
					other.options[key]=nullptr;
				}
				other.byteOrder = nullptr;
				other.majorVersion = nullptr;
				other.minorVersion = nullptr;
				other.sectionLength = nullptr;
				other.options.clear();
			}
			return *this;
		}

		bool sectionHeaderBlock::operator ==(const sectionHeaderBlock &other)
		{
			if (wayne::numberUtil::bytesStaticToNumber(this->byteOrder, wayne::numberUtil::numberTypeReference::DATA_TYPE_INTEGER) != wayne::numberUtil::bytesStaticToNumber(other.byteOrder, wayne::numberUtil::numberTypeReference::DATA_TYPE_INTEGER)) {
				return false;
			}

			if (wayne::numberUtil::bytesStaticToNumber(this->majorVersion, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT) != wayne::numberUtil::bytesStaticToNumber(other.majorVersion, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT)) {
				return false;
			}

			if (wayne::numberUtil::bytesStaticToNumber(this->minorVersion, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT) != wayne::numberUtil::bytesStaticToNumber(other.minorVersion, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT)) {
				return false;
			}

			if (wayne::numberUtil::bytesStaticToNumber(this->sectionLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_LONG) != wayne::numberUtil::bytesStaticToNumber(other.sectionLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_LONG)) {
				return false;
			}

			if (this->options.size() != other.options.size())
			{
				return false;
			}

			if (this->options != other.options)
			{
				return false;
			}
			return true;
		}

		endianTypes sectionHeaderBlock::getByteOrder()
		{
			if (wayne::numberUtil::bytesStaticToNumber(this->byteOrder, wayne::numberUtil::numberTypeReference::DATA_TYPE_INTEGER) != wayne::numberUtil::bytesStaticToNumber(const_cast<char*>(endianTypesBytes::ENDIAN_TYPE_SMALL_BYTES), wayne::numberUtil::numberTypeReference::DATA_TYPE_INTEGER)) {
				return endianTypes::ENDIAN_TYPE_BIG;
			}
			else
			{
				return endianTypes::ENDIAN_TYPE_SMALL;
			}
		}

		char* sectionHeaderBlock::getByteOrderExact()
		{
			char* toReturn = new char[structByteLength::SHB_BYTE_ORDER_LENGTH];
			std::copy(this->byteOrder, this->byteOrder + structByteLength::SHB_BYTE_ORDER_LENGTH, toReturn);
			return toReturn;
		}

		short sectionHeaderBlock::getMajorVersion()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->majorVersion, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT);
		}

		char* sectionHeaderBlock::getMajorVersionExact()
		{
			char* toReturn = new char[structByteLength::SHB_MAJOR_VERSION_LENGTH];
			std::copy(this->majorVersion, this->majorVersion + structByteLength::SHB_MAJOR_VERSION_LENGTH, toReturn);
			return toReturn;
		}

		void sectionHeaderBlock::setMajorVersion(unsigned short newMajorVersion)
		{
			delete[] this->majorVersion;
			this->majorVersion = wayne::numberUtil::numberToBytesStatic(newMajorVersion);
		}

		void sectionHeaderBlock::setMajorVersionExact(const char* newMajorVersion)
		{
			delete[] this->majorVersion;
			this->majorVersion = new char[structByteLength::SHB_MAJOR_VERSION_LENGTH];
			std::copy(newMajorVersion, newMajorVersion + structByteLength::SHB_MAJOR_VERSION_LENGTH, this->majorVersion);
		}

		short sectionHeaderBlock::getMinorVersion()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->minorVersion, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT);
		}

		char* sectionHeaderBlock::getMinorVersionExact()
		{
			char* toReturn = new char[structByteLength::SHB_MINOR_VERSION_LENGTH];
			std::copy(this->minorVersion, this->minorVersion + structByteLength::SHB_MINOR_VERSION_LENGTH, toReturn);
			return toReturn;
		}

		void sectionHeaderBlock::setMinorVersion(unsigned short newMinorVersion)
		{
			delete[] this->minorVersion;
			this->minorVersion = wayne::numberUtil::numberToBytesStatic(newMinorVersion);
		}

		void sectionHeaderBlock::setMinorVersionExact(const char* newMinorVersion)
		{
			delete[] this->minorVersion;
			this->minorVersion = new char[structByteLength::SHB_MINOR_VERSION_LENGTH];
			std::copy(newMinorVersion, newMinorVersion + structByteLength::SHB_MINOR_VERSION_LENGTH, this->minorVersion);
		}

		long sectionHeaderBlock::getSectionLength()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->sectionLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_LONG);
		}

		char* sectionHeaderBlock::getSectionLengthExact()
		{
			char *toReturn = new char[wayne::numberUtil::numberTypeReference::DATA_TYPE_LONG];
			std::copy(this->sectionLength, this->sectionLength + structByteLength::SHB_SECTION_LENGTH_LENGTH, toReturn);
			return toReturn;
		}

		bool sectionHeaderBlock::updateSectionLength(long deltaLength)
		{
			unsigned long currentSectionLength = wayne::numberUtil::bytesStaticToNumber(this->sectionLength, currentSectionLength);
			delete[] this->sectionLength;
			if (currentSectionLength + deltaLength < 0) {
				this->sectionLength = wayne::numberUtil::numberToBytesStatic((unsigned long)0);
				return false;
			} else {
				currentSectionLength += deltaLength;
				this->sectionLength = wayne::numberUtil::numberToBytesStatic(currentSectionLength);
				return true;
			}
		}

		bool sectionHeaderBlock::updateSectionLengthExact(const char* deltaLengthExact)
		{
			long deltaLengthRecovered = wayne::numberUtil::bytesStaticToNumber(const_cast<char*>(deltaLengthExact), deltaLengthRecovered);
			return updateSectionLength(deltaLengthRecovered);
		}

		void sectionHeaderBlock::setSectionLength(unsigned long exactLength)
		{
			delete[] this->sectionLength;
			this->sectionLength = wayne::numberUtil::numberToBytesStatic(exactLength);
		}

		void sectionHeaderBlock::setSectionLengthExact(const char* exactLengthExact)
		{
			delete[] this->sectionLength;
			this->sectionLength = new char[structByteLength::SHB_SECTION_LENGTH_LENGTH];
			std::copy(exactLengthExact, exactLengthExact + structByteLength::SHB_SECTION_LENGTH_LENGTH, this->sectionLength);
		}

		optionTypes* sectionHeaderBlock::getAllOptionsKeys()
		{
			optionTypes* allKeys = new optionTypes[this->options.size()]; // @suppress("Method cannot be resolved") // @suppress("Symbol is not resolved")
			int counter = 0;
			for (auto const& [key, option] : this->options) // @suppress("Symbol is not resolved")
			{
				allKeys[counter] = key;
				counter++;
			}
			return allKeys;
		}

		int sectionHeaderBlock::getAllOptionsCount()
		{
			return this->options.size(); // @suppress("Method cannot be resolved")
		}

		bool sectionHeaderBlock::isOptionExist(optionTypes option)
		{
			//optionTypes* allKeys = new optionTypes[this->options.size()]; // @suppress("Method cannot be resolved") // @suppress("Symbol is not resolved")
			for (auto const& [key, value] : this->options) // @suppress("Symbol is not resolved")
			{
				if (key == option)
				{
					return true;
				}
			}
			return false;

		}

		char* sectionHeaderBlock::getOption(optionTypes option)
		{
			char* toReturn;
			if (isOptionExist(option))
			{
				toReturn = new char[std::strlen(this->options[option])];
				std::copy(this->options[option], this->options[option] + std::strlen(this->options[option]), toReturn);
				return toReturn;
			}
			else
			{
				return nullptr;
			}
		}

		bool sectionHeaderBlock::setOption(optionTypes option, const char* value, unsigned int valueLength)
		{
			if (isOptionAcceptable(option)) {
				int originalOptionLength = 0;
				if (isOptionExist(option)) {	//If Option was already given
					if (isDynamicLengthOption(option)) {
						originalOptionLength = wayne::numberUtil::nextNearestMultOfXFromY((int)std::strlen(this->options[option]), (int)structByteLength::BLOCK_READ_UNIT); // @suppress("Invalid arguments")
						updateBlockLength(-originalOptionLength);				// Decrease the length
						updateBlockLength(wayne::numberUtil::nextNearestMultOfXFromY((int)valueLength, (int)structByteLength::BLOCK_READ_UNIT));
					}
					else
					{
						// Don't do anything. Because there is no static option.
						return false;
					}
				}
				else
				{
					if (isDynamicLengthOption(option)){
						updateBlockLength((int)4 + wayne::numberUtil::nextNearestMultOfXFromY((int)valueLength, (int)structByteLength::BLOCK_READ_UNIT));
						// The first 4 bytes is 2 for option title and 2 for option length.
					}
					else
					{
						// Don't do anything. Because there is no static option.
						return false;
					}
				}
				delete[] this->options[option];
				this->options[option] = new char[valueLength];
				std::copy(value, value + valueLength, this->options[option]);
				return true;
			}
			else
			{
				return false;
			}
		}

		bool sectionHeaderBlock::isOptionAcceptable(optionTypes option)
		{
			switch (option)
			{
			case optionTypes::SHB_HARDWARE:
			case optionTypes::SHB_OS:
			case optionTypes::SHB_USERAPPL:
				return true;
				break;
			default:
				return false;
				break;
			}
		}

		bool sectionHeaderBlock::isDynamicLengthOption(optionTypes option)
		{
			switch (option)
			{
			case optionTypes::SHB_HARDWARE:
			case optionTypes::SHB_OS:
			case optionTypes::SHB_USERAPPL:
				return true;
				break;
			default:
				return false;
				break;
			}
		}

		bool sectionHeaderBlock::isStaticLengthOption(optionTypes option)
		{
			return false;
		}


	} /* namespace PCAP */
} /* namespace wayne */
