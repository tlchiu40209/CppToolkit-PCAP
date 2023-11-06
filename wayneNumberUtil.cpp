/*
 * wayneNumberUtil.cpp
 *
 *  Created on: 2023年10月22日
 *      Author: weich
 */

#include "wayneNumberUtil.hpp"

namespace wayne {
	namespace numberUtil {
		bool isBigEndian()
		{
			short int testWord = 0x0001;
			char* testByte = (char*) &testWord;
			return (testByte[0] == '\x00' ? true : false);
		}
	} /* namespace numberUtil */
} /* namespace wayne */
