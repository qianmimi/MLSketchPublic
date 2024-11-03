/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 28
#define SKETCH_CELL_BIT_WIDTH 64

header share_metadata_t {
    bit<8> appID;
    bit<8> width;
    bit<8> type;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8> protocol;
    bit<1> matchFlag;
    bit<1> hi_Flag;
    bit<1> lo_Flag;
    bit<16> delta_lo;
    bit<32> delta_hi;  
    bit<1> reg_groupID;
    bit<4> rsvd;   
};

struct metadata_t {
    share_metadata_t share_metadata;
};


#define SKETCH_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch##num


/*#define SKETCH_COUNT(num, algorithm) hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<16>)0, {(bit<32>)1}, (bit<32>)SKETCH_BUCKET_LENGTH);\
 sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
 meta.value_sketch##num = meta.value_sketch##num +1; \
 sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)
*/

#define SKETCH_COUNT(num, algorithm) hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.srcAddr, \
 hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)SKETCH_BUCKET_LENGTH);\
 sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
 meta.value_sketch##num = meta.value_sketch##num +1; \
 sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) app_pkts_cnt;
    register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) app_pkts_total_cnt;
    register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) app_miss_cnt;
    register<bit<SKETCH_CELL_BIT_WIDTH>>(1) gmrPointer;
    register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) slotPointer;

    SKETCH_REGISTER(0);
    SKETCH_REGISTER(1);
    SKETCH_REGISTER(2);
    //SKETCH_REGISTER(3);
    //SKETCH_REGISTER(4);

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action sketch_count(){
        SKETCH_COUNT(0, crc32_custom);
        SKETCH_COUNT(1, crc32_custom);
        SKETCH_COUNT(2, crc32_custom);
        //SKETCH_COUNT(3, crc32_custom);
        //SKETCH_COUNT(4, crc32_custom);
    }

   action set_egress_port(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    table forwarding {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_port;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop;
    }

   action set_app_para(bit<8> width, bit<8> type, bit<8> app_id){
        share_metadata.width = wide;
        share_metadata.type = type;
        share_metadata.app_id = app_id;
    }

    table init_tbl {
        key = {
            standard_metadata.ingress_port: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            set_app_para;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action incr_pkt_total_num(){
        app_pkts_total_cnt.read(share_metadata.pkts_total_cnt, share_metadata.app_id);
        share_metadata.pkts_total_cnt = share_metadata.pkts_total_cnt + 1;
        app_pkts_total_cnt.write(share_metadata.app_id,share_metadata.pkts_total_cnt);
    }

    table total_incr_total_pkt_tbl {
        actions = {
            incr_pkt_total_num;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action read_gmrPointer(){
        gmrPointer.read(share_metadata.gmrPointer, 0);
    }

    table read_gmrPointer_tbl {
        actions = {
            read_gmrPointer;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action read_slotIDPointer(){
        slotPointer.read(share_metadata.slotIDPos, share_metadata.gmrPointer);
    }

    table read_slotIDPointer_tbl {
        actions = {
            read_slotIDPointer;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }


        //Read counters
        app_pkts_cnt.read(share_metadata.pkts_cnt, share_metadata.app_id);
        app_pkts_total_cnt.read(share_metadata.pkts_total_cnt, share_metadata.app_id);
        app_miss_cnt.read(share_metadata.miss_cnt, share_metadata.app_id);

        share_metadata.pkts_cnt = share_metadata.pkts_cnt + 1;
        share_metadata.pkts_total_cnt = share_metadata.pkts_total_cnt + 1;
        share_metadata.miss_cnt = share_metadata.miss_cnt + 1;

        //write counters

        app_pkts_cnt.write(share_metadata.app_id,share_metadata.pkts_cnt);
        app_pkts_total_cnt.write(share_metadata.app_id,share_metadata.pkts_total_cnt);
        app_miss_cnt.write(share_metadata.app_id,share_metadata.miss_cnt);

   action set_partition_block(bit<8> hstart, bit<8> hend, bit<32> voff){
        share_metadata.hstart = hstart;
        share_metadata.hend = hend;
        share_metadata.voff = voff;
    }

    table parti_tbl {
        key = {
            standard_metadata.slotID: exact; 
        }
        actions = {
            set_partition_block;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }


    apply {
        read_slotPointer_tbl.apply();
        total_pkt_tbl.apply();
        init_tbl.apply();
        parti_tbl.apply();
        read_slotIDPointer_tbl.apply();
        //apply sketch
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
            sketch_count();
        }

        forwarding.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
