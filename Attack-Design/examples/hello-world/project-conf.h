#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

//LOGGING
#define LOG_CONF_LEVEL_RPL                         LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_TCPIP                       LOG_LEVEL_NONE 
#define LOG_CONF_LEVEL_IPV6                        LOG_LEVEL_NONE 
#define LOG_CONF_LEVEL_6LOWPAN                     LOG_LEVEL_NONE 
#define LOG_CONF_LEVEL_MAC                         LOG_LEVEL_NONE 
#define LOG_CONF_LEVEL_FRAMER                      LOG_LEVEL_NONE 
#define TSCH_LOG_CONF_PER_SLOT                     0


#undef IEEE802154_CONF_DEFAULT_CHANNEL
#define IEEE802154_CONF_DEFAULT_CHANNEL 23
#undef IEEE802154_CONF_PANID
#define IEEE802154_CONF_PANID          0xABD9


//SECURITY
// #define LLSEC802154_CONF_ENABLED 1
// #define CSMA_CONF_LLSEC_SECURITY_LEVEL 5
// #define CSMA_CONF_LLSEC_KEY_ID_MODE 2
// #define CSMA_CONF_LLSEC_DEFAULT_KEY0 {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00}
//COPY END
#endif
