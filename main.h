#ifndef _MAIN_H
#define _MAIN_H


#pragma pack(push, 1)

typedef struct _radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flag;
    uint32_t dummy_data;
} radiotap_header;

typedef struct _dot11_header {
    uint8_t frame_control_version : 2;
    uint8_t frame_control_type : 2;
    uint8_t frame_control_subtype : 4;
    uint8_t flags; 
    uint16_t duration;
    uint8_t destination_addr[6];
    uint8_t source_addr[6];
    uint8_t bssid_addr[6];
    uint16_t sequence_number;
} dot11_header;

typedef struct _fixed_parameter {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
} f_param;

typedef struct _tagged_parameter {
    uint8_t tag_number;
    uint8_t tag_length;
} t_param;

// + add tag_num_value to input hex value in proper addr offset

enum tag_num_value {
		TagSsidParameterSet = 0,
		TagSupportedRated = 1,
		TagDsParameterSet = 3,
		TagTrafficIndicationMap = 5,
		TagCountryInformation = 7,
		TagQbssLoadElement = 11,
		TagHtCapabilities = 45,
		TagRsnInformation = 48,
		TagHtInformation = 61,
		TagVendorSpecific = 221
};


#pragma pack(pop)

#endif
