#pragma once

#include <stdint.h>
#include "radic_settings.h"
#include "crc16_xmodem.h"

enum radic_packet_type {
    radic_packet_type_data = 0, // when transmitting data
    radic_packet_type_resend = 1, // when re-transmitting a corrupted packet
    radic_packet_type_header = 2, // transmitted before the first packet in a message
    radic_packet_type_rsp = 3, // response packet
};

typedef uint8_t radic_packet_type_t;

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
    ret = crc16_calculate(((uint8_t*)packet + 2), 3, 0);
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

radic_err_t delete_packet(radic_packet_t *packet) {

    if ( packet == NULL ) { return radic_err_none; }
    if ( packet->data != NULL ) { radic_free(packet->data); }

    radic_free(packet);

    return radic_err_none;

}

radic_err_t bytes_to_packet(radic_packet_t *packet, uint8_t *bytes, int len) {

    if ( bytes == NULL ) { return radic_err_nullptr; }
    if ( len == 0 ) { return radic_err_none; }

    // initialize the packet
    radic_err_t ret = init_packet(packet);
    if ( ret ) { return ret; }

    // copy packet header
    memcpy(&packet->header, bytes, sizeof(radic_packet_header_t));

    // check that the buffer is the right size
    int bytes_left = len - sizeof(radic_packet_header_t);
    if ( bytes_left < packet->header.len ) { return radic_err_packet; }

    // allocate packet
    ret = allocate_packet_buffer(packet);
    if ( ret ) { return ret; }

    // move data over to the packet
    memcpy(packet->data, (bytes + sizeof(radic_packet_header_t)), packet->header.len);

    return radic_err_none;

}

radic_err_t packet_to_bytes(radic_packet_t *packet, uint8_t *bytes) {

    if ( packet == NULL ) { return radic_err_nullptr; }

    // allocate the byte buffer
    if ( bytes == NULL ) { 
        bytes = (uint8_t*)radic_malloc(packet->header.len + sizeof(radic_packet_header_t));
        if ( bytes == NULL ) { return radic_err_memory; }
    }

    // move header into the buffer
    memcpy(bytes, &packet->header, sizeof(radic_packet_header_t));

    // move data into the buffer
    if ( packet->header.len != 0 ) {
        if ( packet->data == NULL ) { return radic_err_nullptr; }
        memcpy(bytes+sizeof(radic_packet_header_t), packet->data, packet->header.len);
    }

    return radic_err_none;

}