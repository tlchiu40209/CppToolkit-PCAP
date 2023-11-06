/*
 * wayneNumberUtil.hpp
 *
 *  Created on: 2023年11月06日
 *      Author: weich
 */

#ifndef LIB_WAYNENUMBERUTIL_HPP_
#define LIB_WAYNENUMBERUTIL_HPP_
#include <vector>
#include "wayneIO.hpp"

namespace wayne {

	namespace numberUtil {

		enum numberDataLength {
			SHORT_DATA_LENGTH = 2,
			INTEGER_DATA_LENGTH = 4,
			LONG_DATA_LENGTH = 8
		};

		enum numberByteOrder {
			ORDER_DATA_DEFAULT = 0,
			ORDER_DATA_SMALL_ENDIAN = 1,
			ORDER_DATA_BIG_ENDIAN = 2
		};

		class numberTypeReference {
			public:
				static const short DATA_TYPE_SHORT = 0;
				static const unsigned short DATA_TYPE_UNSIGNED_SHORT = 0;
				static const int DATA_TYPE_INTEGER = 0;
				static const unsigned int DATA_TYPE_UNSIGNED_INTEGER = 0;
				static const long DATA_TYPE_LONG = 0;
				static const unsigned long DATA_TYPE_UNSIGNED_LONG = 0;
				static const long long DATA_TYPE_LONG_LONG = 0;
				static const unsigned long long DATA_TYPE_UNSIGNED_LONG_LONG = 0;
		};
		
		bool isBigEndian();
		
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
		
		template<typename integerType> std::vector<char> numberToBytes(integerType const& number, numberByteOrder numByteOrder);
		template<typename integerType> char* numberToBytesStatic(integerType const& number, numberByteOrder numByteOrder);
		template<typename integerType> integerType bytesToNumber(std::vector<char> rawBytes, integerType const& referenceType, numberByteOrder rawByteOrder);
		template<typename integerType> integerType bytesStaticToNumber(char* rawBytes, integerType const& referenceType, numberByteOrder rawByteOrder);
		template<typename integerType> integerType nextNearestMultOfXFromY(integerType const& y, integerType const& x);

	} /* namespace numberUtil */
} /* namespace wayne */

#endif /* LIB_WAYNENUMBERUTIL_HPP_ */
