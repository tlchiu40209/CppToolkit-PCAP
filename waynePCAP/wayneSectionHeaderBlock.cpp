/*
 * wayneSectionHeaderBlock.cpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#include "wayneSectionHeaderBlock.hpp"

namespace wayne {
	namespace PCAP {

		sectionHeaderBlock::sectionHeaderBlock() {
			//block();
			this->byteOrder = new char[std::strlen(byteSeqs::BYTE_ORDER_SMALL_ENDIAN)];
			std::strncpy(this->byteOrder, byteSeqs::BYTE_ORDER_SMALL_ENDIAN, std::strlen(byteSeqs::BYTE_ORDER_SMALL_ENDIAN));
			this->majorVersion = new char[]{"\x00\x01"};
			this->minorVersion = new char[]{"\x00\x00"};
			this->sectionLength = new char[]{"\x00\x00\x00\x00\x00\x00\x00\x00"};
		}

		sectionHeaderBlock::sectionHeaderBlock(endianTypes initByteOrder)
		{
			switch (initByteOrder)
			{
			case endianTypes::BIG:
				this->byteOrder = new char[std::strlen(byteSeqs::BYTE_ORDER_BIG_ENDIAN)];
				std::strncpy(this->byteOrder, byteSeqs::BYTE_ORDER_BIG_ENDIAN, std::strlen(byteSeqs::BYTE_ORDER_BIG_ENDIAN));
				break;
			case endianTypes::SMALL:
				this->byteOrder = new char[std::strlen(byteSeqs::BYTE_ORDER_SMALL_ENDIAN)];
				std::strncpy(this->byteOrder, byteSeqs::BYTE_ORDER_SMALL_ENDIAN, std::strlen(byteSeqs::BYTE_ORDER_SMALL_ENDIAN));
				break;
			}
			this->majorVersion = new char[]{"\x00\x01"};
			this->minorVersion = new char[]{"\x00\x00"};
			this->sectionLength = new char[]{"\x00\x00\x00\x00\x00\x00\x00\x00"};
		}

		sectionHeaderBlock::sectionHeaderBlock(const char* initByteOrderExact)
		{
			if (std::strcmp(initByteOrderExact, byteSeqs::BYTE_ORDER_BIG_ENDIAN) == 0)
			{
				this->byteOrder = new char[std::strlen(byteSeqs::BYTE_ORDER_BIG_ENDIAN)];
				std::strncpy(this->byteOrder, byteSeqs::BYTE_ORDER_BIG_ENDIAN, std::strlen(byteSeqs::BYTE_ORDER_BIG_ENDIAN));
			}
			else
			{
				this->byteOrder = new char[std::strlen(byteSeqs::BYTE_ORDER_SMALL_ENDIAN)];
				std::strncpy(this->byteOrder, byteSeqs::BYTE_ORDER_SMALL_ENDIAN, std::strlen(byteSeqs::BYTE_ORDER_SMALL_ENDIAN));
			}
			this->majorVersion = new char[]{"\x00\x01"};
			this->minorVersion = new char[]{"\x00\x00"};
			this->sectionLength = new char[]{"\x00\x00\x00\x00\x00\x00\x00\x00"};
		}

		sectionHeaderBlock::sectionHeaderBlock(endianTypes initByteOrder, size_t initMajorVersion, size_t initMinorVersion)
		{
			//Here
		}

		sectionHeaderBlock::sectionHeaderBlock(const char* initByteOrderExact, const char* initMajorVersionExact, const char* initMinorVersionExact)
		{
			//Here
		}

		sectionHeaderBlock::~sectionHeaderBlock() {
			/* Note: ~block() will be triggered automatically */
			delete[] this->byteOrder;
			delete[] this->majorVersion;
			delete[] this->minorVersion;
			delete[] this->sectionLength;
			for (auto const& [key, option] : this->options) // @suppress("Symbol is not resolved")
			{
				delete[] option;
			}
			options.clear(); // @suppress("Method cannot be resolved")
		}

		sectionHeaderBlock::sectionHeaderBlock(const sectionHeaderBlock &other) {
			//block(other);
			delete[] this->byteOrder;
			this->byteOrder = new char[std::strlen(other.byteOrder)];
			std::strncpy(this->byteOrder, other.byteOrder, std::strlen(other.byteOrder));
			delete[] this->majorVersion;
			this->majorVersion = new char[std::strlen(other.majorVersion)];
			std::strncpy(this->majorVersion, other.majorVersion, std::strlen(other.majorVersion));
			delete[] this->minorVersion;
			this->minorVersion = new char[std::strlen(other.minorVersion)];
			std::strncpy(this->minorVersion, other.minorVersion, std::strlen(other.minorVersion));
			delete[] this->sectionLength;
			this->sectionLength = new char[std::strlen(other.sectionLength)];
			std::strncpy(this->sectionLength, other.sectionLength, std::strlen(other.sectionLength));
			for (auto const& [key, option] : other.options) // @suppress ("Method cannot be resolved") // @suppress("Symbol is not resolved")
			{
				char* newOption = new char[std::strlen(option)]; // @suppress("Invalid arguments")
				std::strncpy(newOption, option, std::strlen(option)); // @suppress("Invalid arguments")
				this->options.insert(std::pair<optionTypes, char*>(key, newOption)); // @suppress("Symbol is not resolved") // @suppress("Method cannot be resolved")
			}
		}

		sectionHeaderBlock::sectionHeaderBlock(sectionHeaderBlock &&other) {
			//block(other);
			delete[] this->byteOrder;
			this->byteOrder = new char[std::strlen(other.byteOrder)];
			std::strncpy(this->byteOrder, other.byteOrder, std::strlen(other.byteOrder));
			delete[] other.byteOrder;

			delete[] this->majorVersion;
			this->majorVersion = new char[std::strlen(other.majorVersion)];
			std::strncpy(this->majorVersion, other.majorVersion, std::strlen(other.majorVersion));
			delete[] other.majorVersion;

			delete[] this->minorVersion;
			this->minorVersion = new char[std::strlen(other.minorVersion)];
			std::strncpy(this->minorVersion, other.minorVersion, std::strlen(other.minorVersion));
			delete[] other.minorVersion;

			delete[] this->sectionLength;
			this->sectionLength = new char[std::strlen(other.sectionLength)];
			std::strncpy(this->sectionLength, other.sectionLength, std::strlen(other.sectionLength));
			delete[] other.sectionLength;

			for (auto const& [key, option] : other.options) // @suppress ("Method cannot be resolved") // @suppress("Symbol is not resolved")
			{
				char* newOption = new char[std::strlen(option)]; // @suppress("Invalid arguments")
				std::strncpy(newOption, option, std::strlen(option)); // @suppress("Invalid arguments")
				this->options.insert(std::pair<optionTypes, char*>(key, newOption)); // @suppress("Symbol is not resolved") // @suppress("Method cannot be resolved")
				delete[] option;
			}
			other.options.clear(); // @suppress("Method cannot be resolved")
		}

		sectionHeaderBlock& sectionHeaderBlock::operator=(const sectionHeaderBlock &other) {
			if (this != &other)
			{
				//block(other);
				delete[] this->byteOrder;
				this->byteOrder = new char[std::strlen(other.byteOrder)];
				std::strncpy(this->byteOrder, other.byteOrder, std::strlen(other.byteOrder));
				delete[] this->majorVersion;
				this->majorVersion = new char[std::strlen(other.majorVersion)];
				std::strncpy(this->majorVersion, other.majorVersion, std::strlen(other.majorVersion));
				delete[] this->minorVersion;
				this->minorVersion = new char[std::strlen(other.minorVersion)];
				std::strncpy(this->minorVersion, other.minorVersion, std::strlen(other.minorVersion));
				delete[] this->sectionLength;
				this->sectionLength = new char[std::strlen(other.sectionLength)];
				std::strncpy(this->sectionLength, other.sectionLength, std::strlen(other.sectionLength));
				for (auto const& [key, option] : other.options) // @suppress ("Method cannot be resolved") // @suppress("Symbol is not resolved")
				{
					char* newOption = new char[std::strlen(option)]; // @suppress("Invalid arguments")
					std::strncpy(newOption, option, std::strlen(option)); // @suppress("Invalid arguments")
					this->options.insert(std::pair<optionTypes, char*>(key, newOption)); // @suppress("Symbol is not resolved") // @suppress("Method cannot be resolved")
				}
			}
			return *this;
		}

		sectionHeaderBlock& sectionHeaderBlock::operator=(sectionHeaderBlock &&other) {
			if (this != &other)
			{
				//block(other);
				delete[] this->byteOrder;
				this->byteOrder = new char[std::strlen(other.byteOrder)];
				std::strncpy(this->byteOrder, other.byteOrder, std::strlen(other.byteOrder));
				delete[] other.byteOrder;

				delete[] this->majorVersion;
				this->majorVersion = new char[std::strlen(other.majorVersion)];
				std::strncpy(this->majorVersion, other.majorVersion, std::strlen(other.majorVersion));
				delete[] other.majorVersion;

				delete[] this->minorVersion;
				this->minorVersion = new char[std::strlen(other.minorVersion)];
				std::strncpy(this->minorVersion, other.minorVersion, std::strlen(other.minorVersion));
				delete[] other.minorVersion;

				delete[] this->sectionLength;
				this->sectionLength = new char[std::strlen(other.sectionLength)];
				std::strncpy(this->sectionLength, other.sectionLength, std::strlen(other.sectionLength));
				delete[] other.sectionLength;

				for (auto const& [key, option] : other.options) // @suppress ("Method cannot be resolved") // @suppress("Symbol is not resolved")
				{
					char* newOption = new char[std::strlen(option)]; // @suppress("Invalid arguments")
					std::strncpy(newOption, option, std::strlen(option)); // @suppress("Invalid arguments")
					this->options.insert(std::pair<optionTypes, char*>(key, newOption)); // @suppress("Symbol is not resolved") // @suppress("Method cannot be resolved")
					delete[] option;
				}
				other.options.clear(); // @suppress("Method cannot be resolved")
			}
			return *this;
		}

		bool sectionHeaderBlock::operator ==(const sectionHeaderBlock &other)
		{
			bool isEqual = true;
			if (isEqual && std::strcmp(this->byteOrder, other.byteOrder) != 0)
			{
				isEqual = false;
			}
			if (isEqual && std::strcmp(this->majorVersion, other.majorVersion) != 0)
			{
				isEqual = false;
			}
			if (isEqual && std::strcmp(this->minorVersion, other.minorVersion) != 0)
			{
				isEqual = false;
			}
			if (isEqual && std::strcmp(this->sectionLength, other.sectionLength) != 0)
			{
				isEqual = false;
			}
			if (isEqual &&  this->options.size() != other.options.size()) // @suppress("Method cannot be resolved")
			{
				isEqual = false;
			}
			if (isEqual && this->options != other.options)
			{
				isEqual = false;
			}
			return isEqual;
		}

		endianTypes sectionHeaderBlock::getByteOrder()
		{
			if (std::strcmp(this->byteOrder, byteSeqs::BYTE_ORDER_BIG_ENDIAN) == 0)
			{
				return endianTypes::BIG;
			}
			else
			{
				return endianTypes::SMALL;
			}
		}

		char* sectionHeaderBlock::getByteOrderExact()
		{
			char* toReturn = new char[std::strlen(this->byteOrder)];
			std::strncpy(toReturn, this->byteOrder, std::strlen(this->byteOrder));
			return toReturn;
		}

		size_t sectionHeaderBlock::getMajorVersion()
		{
			return (size_t)*this->majorVersion;
		}

		char* sectionHeaderBlock::getMajorVersionExact()
		{
			char* toReturn = new char[std::strlen(this->majorVersion)];
			std::strncpy(toReturn, this->majorVersion, std::strlen(this->majorVersion));
			return toReturn;
		}

		void sectionHeaderBlock::setMajorVersion(size_t newMajorVersion)
		{
			delete[] this->majorVersion;
			if (newMajorVersion >= 65535)
			{
				this->majorVersion = new char[]{"\xFF\xFF"};
			}
			else
			{
				this->minorVersion = new char[std::strlen((char*)&newMajorVersion)];
				std::strncpy(this->minorVersion, (char*)&newMajorVersion, std::strlen((char*)&newMajorVersion));
			}
		}

		void sectionHeaderBlock::setMajorVersionExact(const char* newMajorVersion)
		{
			delete[] this->majorVersion;
			if (std::strlen(newMajorVersion) > 2)
			{
				this->majorVersion = new char[]{"\xFF\xFF"};
			}
			else
			{
				this->majorVersion = new char[std::strlen(newMajorVersion)];
				std::strncpy(this->majorVersion, newMajorVersion, std::strlen(newMajorVersion));
			}
		}

		size_t sectionHeaderBlock::getMinorVersion()
		{
			return (size_t)*this->minorVersion;
		}

		char* sectionHeaderBlock::getMinorVersionExact()
		{
			char* toReturn = new char[std::strlen(this->minorVersion)];
			std::strncpy(toReturn, this->minorVersion, std::strlen(this->minorVersion));
			return toReturn;
		}

		void sectionHeaderBlock::setMinorVersion(size_t newMinorVersion)
		{
			delete[] this->minorVersion;
			if (newMinorVersion >= 65535)
			{
				this->minorVersion = new char[]{"\xFF\xFF"};
			}
			else
			{
				this->minorVersion = new char[std::strlen((char*)&newMinorVersion)];
				std::strncpy(this->minorVersion, (char*)&newMinorVersion, std::strlen((char*)&newMinorVersion));
			}
		}

		void sectionHeaderBlock::setMinorVersionExact(const char* newMinorVersion)
		{
			delete[] this->minorVersion;
			if (std::strlen(newMinorVersion) > 2)
			{
				this->minorVersion = new char[]{"\xFF\xFF"};
			}
			else
			{
				this->minorVersion = new char[std::strlen(newMinorVersion)];
				std::strncpy(this->minorVersion, newMinorVersion, std::strlen(newMinorVersion));
			}
		}





	} /* namespace PCAP */
} /* namespace wayne */
