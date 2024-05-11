#pragma once

#include <radic_packet.h>
#include <radic_settings.h>

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

        message->packets = (radic_packet_t*)radic_malloc(sizeof(radic_packet_t)*message->num_packets);
        if ( message->packets == NULL ) { return radic_err_memory; }

        // initialize every packet
        for ( int i = 0; i < message->num_packets; i++ ) {
            radic_err_t err = init_packet(&message->packets[i]);
            if ( err ) { return err; }
        }

    }

    // we can't receive the header twice!
    if ( packet->header.type == radic_packet_type_header ) { return radic_err_msgorder; }

}

