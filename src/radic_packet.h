#pragma once

#include <stdint.h>
#include <radic_settings.h>
#include <crc16_xmodem.h>

typedef enum radic_packet_type: uint8_t {
    radic_packet_type_data = 0, // when transmitting data
    radic_packet_type_resend = 1, // when re-transmitting a corrupted packet
    radic_packet_type_header = 2, // transmitted before the first packet in a message
    radic_packet_type_chksum_fail = 3, // when notifying receiver that a checksum failed
} radic_packet_type_t;

typedef struct {
    uint16_t checksum;
    radic_packet_type_t type;
    uint8_t msg_idx;
    uint8_t len;
    uint8_t unused;
} radic_packet_header_t;

typedef struct {
    radic_packet_header_t header;
    uint8_t* data;
} radic_packet_t;

uint16_t calculate_packet_checksum(radic_packet_t* packet) {
    uint16_t ret;
    if ( packet == NULL ) { return 0; }
    ret = crc16_calculate(((uint8_t*)packet + 3), 3, 0);
    if ( packet->data == NULL ) { return ret; }
    ret = crc16_calculate(packet->data, packet->header.len, ret);
    return ret;
}

radic_err_t check_packet_checksum(radic_packet_t* packet, uint16_t* checksum) {
    if ( packet == NULL ) { return radic_err_nullptr; }
    
    uint16_t tmp = calculate_packet_checksum(packet);
    if ( checksum != NULL ) { *checksum = tmp; }

    if (tmp == packet->header.checksum) { return radic_err_none; }
    return radic_err_checksum;
}

radic_err_t allocate_packet_buffer(radic_packet_t* packet) {
    if ( packet == NULL ) { return radic_err_nullptr; }

    if ( packet->data == NULL && packet->header.len != 0 ) {
        packet->data = (uint8_t*)radic_malloc(packet->header.len*sizeof(uint8_t));
        if ( packet->data == NULL ) { return radic_err_memory; }
    }

    return radic_err_none;
}

radic_err_t init_packet(radic_packet_t* packet) {
    
    // if this packet is dynamically allocated, allocate it
    if ( packet == NULL ) { 
        packet = (radic_packet_t*)radic_malloc(sizeof(radic_packet_t)); 
        if ( packet == NULL ) { return radic_err_memory; }    
    }

    memset(packet, 0, sizeof(radic_packet_t));
    
    return radic_err_none;

}