/*
 * waynePCAP.hpp
 *
 *  Created on: 2023年10月7日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_HPP_
#define LIB_WAYNEPCAP_HPP_
#include <map>
#include <string>

namespace wayne {
    namespace PCAP
    {

        class PCAPNG
        {
            PCAPNG();
            virtual ~PCAPNG();
            PCAPNG(PCAPNG &&other);
            PCAPNG& operator=(const PCAPNG &other);
            PCAPNG& operator=(PCAPNG &other);
            PCAPNG& operator==(const PCAPNG &other);
            PCAPNG& operator==(PCAPNG &other);
        };

    }
} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_HPP_ */
