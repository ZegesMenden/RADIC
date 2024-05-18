#pragma once

#include "radic_packet.h"
#include "radic_settings.h"

#ifndef min
#define min(a, b) (a < b ? a : b)
#endif

typedef struct {

    uint8_t num_packets;
    radic_packet_t* packets;

} radic_message_t;

radic_err_t process_packet(radic_message_t* message, radic_packet_t* packet, radic_packet_t *rsp) {
    
    if ( message == NULL || packet == NULL ) { return radic_err_nullptr; }

    // reject the packet if the checksum doesnt pass
    if ( check_packet_checksum(packet, NULL) ) { return radic_err_checksum; }

    // if we haven't received any messages yet
    if ( message->num_packets == 0 ) {

        // if we haven't received a header yet, we cant process messages
        if ( packet->header.type != radic_packet_type_header ) { return radic_err_msgorder; }

        message->num_packets = packet->header.msg_idx;
        if ( message->num_packets == 0 ) { return radic_err_packet; } 

        message->packets = (radic_packet_t*)radic_malloc(sizeof(radic_packet_t*)*message->num_packets);
        if ( message->packets == NULL ) { return radic_err_memory; }

        // initialize every packet
        for ( int i = 0; i < message->num_packets; i++ ) {
            radic_err_t err = init_packet(&message->packets[i]);
            if ( err ) { return err; }
        }

    }

    // only process data and resend packets
    if ( packet->header.type != radic_packet_type_data && packet->header.type != radic_packet_type_resend ) { return radic_err_msgorder; }

    // packet is either corrupted or from the wrong message
    if ( packet->header.msg_idx >= message->num_packets ) { return radic_err_packet; }

    // packet is trying to overwrite existing data
    if ( message->packets[packet->header.msg_idx].data != NULL && packet->header.type == radic_packet_type_data ) { return radic_err_packet; } 

    // copy the packet into the message buffer
    memcpy(&message->packets[packet->header.msg_idx], packet, sizeof(radic_packet_t));

}

int message_n_missing_packets(radic_message_t *message) {

    if ( message == NULL ) { return -1; }
    if ( message->packets == NULL ) { return -1; }

    int n_missing_packets = 0;

    for ( int i = 0; i < message->num_packets; i++ ) {
        n_missing_packets += message->packets[i].header.msg_idx != i;
    }

    return n_missing_packets;

}

int message_is_complete(radic_message_t *message) {

    if ( message == NULL ) { return 0; }
    if ( message->packets == NULL ) { return 0; }

    return message_n_missing_packets(message) != 0;

}

radic_err_t generate_rsp_packet(radic_message_t *message, radic_packet_t *packet) {

    if ( message == NULL || message->packets == NULL ) { return radic_err_nullptr; }

    // initialize the rsp packet
    init_packet(packet);

    packet->header.type = radic_packet_type_rsp;

    int missing_packets = message_n_missing_packets(message);

    if ( missing_packets > 0 ) {
        
        packet->data = (uint8_t*)radic_malloc(sizeof(uint8_t)*missing_packets);
        packet->header.len = missing_packets;

        int packet_position = 0;
        for ( int i = 0; i < message->num_packets; i++ ) {
            if ( message->packets[i].header.msg_idx != i ) {
                packet->data[packet_position++] = i;
            }
        }

    }

    packet->header.checksum = calculate_packet_checksum(packet);

    return radic_err_none;

}

radic_err_t delete_message(radic_message_t *message) {

    if ( message == NULL ) { return radic_err_none; }

    if ( message->packets != NULL ) {
        for ( int i = 0; i < message->num_packets; i++ ) {
            delete_packet(&message->packets[i]);
        }
    }

    radic_free(message);

    return radic_err_none;

}

int message_len(radic_message_t *message) {

    if ( message == NULL ) { return 0; }
    if ( message->packets == NULL ) { return 0; }

    int ret = 0;
    for ( int i = 0; i < message->num_packets; i++ ) {
        ret += message->packets[i].header.len;
    }

    return ret;

}

radic_err_t get_message_contents(radic_message_t *message, uint8_t *bytes) {

    if ( bytes != NULL ) { return radic_err_memory; }
    
    int len = message_len(message);

    bytes = (uint8_t*)radic_malloc(len);
    if ( bytes == NULL ) { return radic_err_memory; }

    uint8_t *buf_pos = bytes;
    for ( int i = 0; i < message->num_packets; i++ ) {
        if ( message->packets[i].data == NULL ) { return radic_err_nullptr; }
        memcpy(buf_pos, message->packets[i].data, message->packets[i].header.len);
        buf_pos += message->packets[i].header.len;
    }

    return radic_err_none;

}

radic_err_t bytes_to_message(radic_message_t *message, uint8_t *bytes, int len) {

    // don't make a message if there is no data
    if ( len == 0 ) { return radic_err_none; }

    int max_packet_len = 10;

    if ( message == NULL ) { 
        message = (radic_message_t*)radic_malloc(sizeof(radic_message_t));
        if ( message == NULL ) { return radic_err_memory; }
    }

    // number of packets needed
    message->num_packets = 1 + (len + (max_packet_len-1))/max_packet_len;
    
    // allocate packets
    message->packets = (radic_packet_t*)radic_malloc(sizeof(radic_packet_t)*message->num_packets);
    if ( message->packets == NULL ) { return radic_err_memory; }

    // initialize the packets
    memset(&message->packets[0], 0, sizeof(radic_packet_header_t));
    message->packets[0].header.type = radic_packet_type_header;
    message->packets[0].header.msg_idx = message->num_packets - 1;
    message->packets[0].header.checksum = calculate_packet_checksum(&message->packets[0]);

    int byte_positon = 0;
    radic_err_t ret;

    for ( int i = 1; i < message->num_packets; i++ ) {
        int data_sz = min(max_packet_len, len - byte_positon);
        init_packet(&message->packets[i]);
        message->packets[i].header.len = data_sz;
        message->packets[i].header.type = radic_packet_type_data;
        message->packets[i].header.msg_idx = i-1;
        
        // allocate data buffer
        message->packets[i].data = (uint8_t*)radic_malloc(data_sz);
        if ( message->packets[i].data == NULL ) { return radic_err_memory; }

        // move data into the packet
        memcpy(message->packets[i].data, (bytes + byte_positon), data_sz);
        
        byte_positon += data_sz;
    }

    return radic_err_none;

}

radic_err_t message_to_bytes(radic_message_t *message, uint8_t *bytes) {

    if ( message == NULL ) { return radic_err_nullptr; }
    
    // calculate message size
    int message_size = message_len(message);// + message->num_packets*sizeof(radic_packet_header_t);

    if ( bytes == NULL ) { 
        return radic_err_nullptr;
    }

    // move each packet into the buffer

    int byte_arr_position = 0;
    radic_err_t ret;
    
    for ( int i = 0; i < message->num_packets; i++ ) {
        if ( message->packets[i].data == NULL ) { return radic_err_memory; }
        memcpy((bytes + byte_arr_position), message->packets[i].data, message->packets[i].header.len);
        byte_arr_position += message->packets[i].header.len;
    }

    return radic_err_none;

}