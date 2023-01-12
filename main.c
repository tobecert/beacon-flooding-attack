#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "main.h"

// -------------------------------- -global variable------------------------------

radiotap_header radiotap; // radiotap
dot11_header dot11; // ieee802.11
f_param fixed; // fixed parameter
t_param tagged; // tagged parameter

// -------------------------------------function----------------------------------

void usage() {
    printf("syntax: ./beacon-flood <interface> <ssid-list-file>\n"); // skeleton
    printf("sample: ./beacon-flood mon0 ssid-list.txt\n"); // skeleton
}

typedef struct { // skeleton
    char * dev_;
    char * file_;
} Param;

Param param = { // skeleton
    .dev_ = NULL,
    .file_ = NULL
};

bool parse(Param * param, int argc, char * argv[]) { // skeleton
    
    if (argc != 3) {
        usage();
        return false;
    }
    param->dev_ = argv[1]; // NIC 담기
    param->file_ = argv[2]; // ssid-list.txt 담기
    return true;
}

/*
int get_ssid() {
    const int max = 255;
    char line[max];
    char * pLine;

    FILE * in = fopen("ssid-list.txt", "r");

    if(in == NULL){
		fprintf(stderr, "Failed open ssid-list.txt!\n");
		exit(1);
	}

    while (!feof(in)) {
        pLine = fgets(line, max, in);
        printf("%s", pLine);
    }
    fclose(in);
}
*/

// -------------------------------------Main--------------------------------------

int main(int argc, char * argv[]) {

    const int max = 255;

    char * list_Arr[31] = {0, };
    char * ssid_Arr;

    int cnt = 0;
    int ssid_cnt = 0;

    // skeleton
    if (!parse(&param, argc, argv))
        return -1;

    // skeleton
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t * pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf); // exception
        return -1;
    };

//-----------------------------------File io--------------------------------------
    
    FILE * in = fopen(param.file_, "r");

    if(in == NULL){
		fprintf(stderr, "Failed open ssid-list.txt!\n"); // file exception
		exit(1);
	}

    while (!feof(in)) {
        ssid_Arr = (char *)malloc(sizeof(char) * max);
        fgets(ssid_Arr, max, in);
        list_Arr[cnt] = ssid_Arr;
        //printf("%s", ssid_Arr);
        cnt++;
    }

    //printf("%d\n", cnt);
    
    /*
    for (int i = 0; i < cnt; i++) {
        printf("%s", list_Arr[i]);
    }
    */

    
    fclose(in);


//-------------------------------radiotap-----------------------------------------

    memset(&radiotap, 0x0, sizeof(radiotap)); // value 추가 하는 애들 제외 0x00 memset
    radiotap.length = sizeof(radiotap); // length 설정
    radiotap.present_flag = 0x00028000; // present_flag 0x00028000 add 무조건 필요함.
    
//-------------------------------beacon frame-------------------------------------

    memset(&dot11, 0x0, sizeof(dot11));
    dot11.frame_control_subtype = 0x8;

    // dummy addr 설정
    memcpy(dot11.destination_addr, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(dot11.destination_addr));
    memcpy(dot11.source_addr, "\x12\x34\x56\x11\x22\x33", sizeof(dot11.source_addr));
    memcpy(dot11.bssid_addr, "\x12\x34\x56\x11\x22\x33", sizeof(dot11.bssid_addr));

    
//-------------------------------wireless management------------------------------

    //char timestamp[] = "\xd5\x61\xe0\xc1\xeb\x7f\x00\x00";

    // dummy

    //memcpy(fixed.timestamp, "\xd5\x61\xe0\xc1\xeb\x7f\x00\x00", sizeof(fixed.timestamp));

    fixed.timestamp = 0;
    fixed.beacon_interval = 0x6400;
    fixed.capabilities = 0x0011;

    int tag_len_stack = 0;
    int tag_len_tmp = 0;

    u_int8_t * tag_data;

    
    while (true) {

        // ssid 처리
        tagged.tag_number = TagSsidParameterSet;
        tag_len_tmp = strlen(list_Arr[ssid_cnt]) - 1;
        tagged.tag_length = tag_len_tmp;
        tag_data = (u_int8_t *)malloc(tag_len_tmp);
        memcpy(tag_data, list_Arr[ssid_cnt], tag_len_tmp);
        //printf("ok1\n");

        //tagged.tag_number = TagSupportedRated;
        //tagged.tag_length 

        // ssid length + ssid tag + support rate tag + support rate length + DS tag + DS length + RSN tag + RSN length + vendor tag + vendor length
        size_t packet_size = sizeof(radiotap) + sizeof(dot11) + sizeof(fixed) + tagged.tag_length + 2 + 2 + 8 + 2 + 1 + 2 + 20 + 2 + 24;
        u_char * packet = (u_char *) malloc(packet_size);

        memcpy(packet, &radiotap, sizeof(radiotap));
        memcpy(packet+sizeof(radiotap), &dot11, sizeof(dot11));
        memcpy(packet+sizeof(radiotap)+sizeof(dot11), &fixed, sizeof(fixed));

        // memcpy 
        memcpy(packet+sizeof(radiotap)+sizeof(dot11)+sizeof(fixed), &tagged, 2);
        memcpy(packet+sizeof(radiotap)+sizeof(dot11)+sizeof(fixed) + 2, tag_data, tagged.tag_length);

        u_char * tmp1 = packet+sizeof(radiotap)+sizeof(dot11)+sizeof(fixed) + 2 + tagged.tag_length;

        //(packet_size - tagged.tag_length)

        // Set Supported Rate For iPhone 

        tagged.tag_number = TagSupportedRated;
        tagged.tag_length = 0x8;
        
        // Supported rate dummy value
        char SR_value[] = "\x82\x84\x8B\x96\x24\x30\x48\x6C"; // 1(B), 2(B), 5.5(B), 11(B), 18, 24, 36, 54

        memcpy(tmp1, &tagged, 2);
        memcpy(tmp1 + 2, SR_value, tagged.tag_length);


        // Set DS parameter

        u_char * tmp2 = tmp1 + 2 + tagged.tag_length;

        tagged.tag_number = TagDsParameterSet;
        tagged.tag_length = 0x1;
        
        char channel[] = "\x06"; // dummy channel

        memcpy(tmp2, &tagged, 2);
        memcpy(tmp2 + 2, channel, tagged.tag_length);


        // Set RSN information value

        u_char * tmp3 = tmp2 + 2 + tagged.tag_length;

        tagged.tag_number = TagRsnInformation;
        tagged.tag_length = 0x14;

        // dummy RSN - WPA2 CCMP - PSK
        char RSN[] = "\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00"; 

        memcpy(tmp3, &tagged, 2);
        memcpy(tmp3 + 2, RSN, tagged.tag_length);


        // Set vendor value

        u_char * tmp4 = tmp3 + 2 + tagged.tag_length;

        tagged.tag_number = TagVendorSpecific;
        tagged.tag_length = 0x18;

        // dummy vendor Microsoft Corp.: WMM/WME: Parameter Element
        char vendor[] = "\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00";

        memcpy(tmp4, &tagged, 2);
        memcpy(tmp4 + 2, vendor, tagged.tag_length);

        //printf("ok2\n");

        if (pcap_sendpacket(pcap, packet, packet_size) != 0) {
            fprintf(stderr, "pcap_sendpacket(%s) error\n", param.dev_);
        }

        free(packet);
        free(tag_data);

        if (ssid_cnt + 1 == cnt) {
            ssid_cnt = (ssid_cnt + 1) % cnt;
        }
        else { 
            ssid_cnt++;
        }

    }
    


    free(ssid_Arr);

    pcap_close(pcap);

    return 0;
}