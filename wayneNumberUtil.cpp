/*
 * wayneNumberUtil.cpp
 *
 *  Created on: 2023年10月22日
 *      Author: weich
 */

#include "wayneNumberUtil.hpp"

namespace wayne {
	namespace numberUtil {
		template<typename integerType> std::vector<char> numberToBytes(integerType const& number, numberByteOrder numByteOrder)
		{
			std::vector<char> toReturn;
			for (int i = 0; i < sizeof(number); i++) {
				toReturn.push_back((number >> (i * 8)));
			}
			switch (numByteOrder)
			{
			case numberByteOrder::ORDER_DATA_DEFAULT:
				if (isBigEndian()) {
					std::reverse(toReturn.begin(), toReturn.end());
				}
				break;
			case numberByteOrder::ORDER_DATA_SMALL_ENDIAN:
				break;
			case numberByteOrder::ORDER_DATA_BIG_ENDIAN:
				std::reverse(toReturn.begin(), toReturn.end());
				break;
			}
			return toReturn;
		}

		template<typename integerType> char* numberToBytesStatic(integerType const& number, numberByteOrder numByteOrder)
		{
			std::vector<char> toHandle = numberToBytes(number, numByteOrder);
			char* toReturn = new char[toHandle.size()];
			std::copy(toHandle.begin(), toHandle.end(), toReturn);
			return toReturn;
		}

		template<typename integerType> integerType bytesToNumber(std::vector<char> rawBytes, integerType const& referenceType, numberByteOrder rawByteOrder)
		{
			if (rawBytes.size() != sizeof(referenceType)) {
				wayne::IO::logLn("Provided length of data bytes does not match with the provided reference type", true);
				return 0;
			}
			else
			{
				switch (rawByteOrder)
				{
				case numberByteOrder::ORDER_DATA_DEFAULT:
					break;
				case numberByteOrder::ORDER_DATA_SMALL_ENDIAN:
					if (isBigEndian()) {
						std::reverse(rawBytes.begin(), rawBytes.end());
					}
					break;
				case numberByteOrder::ORDER_DATA_BIG_ENDIAN:
					if (!isBigEndian()) {
						std::reverse(rawBytes.begin(), rawBytes.end());
					}
					break;
				}
				integerType toReturn;
				unsigned char* buffer = new unsigned char[rawBytes.size()];
				std::copy(rawBytes.begin(), rawBytes.end(), buffer);
				toReturn = *((integerType*)buffer);
				delete[] buffer;
				return toReturn;
		    }
		}

		template<typename integerType> integerType bytesStaticToNumber(char* rawBytes, numberDataLength dataLength, integerType const& referenceType, numberByteOrder rawByteOrder)
		{
			std::vector<char> toRecur(dataLength);
			std::copy(rawBytes, rawBytes + dataLength, toRecur);
			return bytesToNumber(toRecur, referenceType, rawByteOrder);
		}

		template<typename integerType> integerType nextNearestMultOfXFromY(integerType const& y, integerType const& x)
		{
			if (y % x == 0) {
				return y;
			}
			else {
				return (x * ((y / x) + 1));
			}
		}

		bool isBigEndian()
		{
			short int testWord = 0x0001;
			char* testByte = (char*) &testWord;
			return (testByte[0] == '\x00' ? true : false);
		}
	} /* namespace numberUtil */
} /* namespace wayne */
