/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 2048
#define SKETCH_BUCKET_LENGTH_fac 1536
#define SKETCH_BUCKET_LENGTH2 4096
#define SKETCH_BUCKET_LENGTH_fac2 3072
#define SKETCH_BUCKET_LENGTH3 8192
#define SKETCH_BUCKET_LENGTH_fac3 6144
#define SKETCH_BUCKET_LENGTH4 16384

#define SKETCH_CELL_BIT_WIDTH 32

#define store_srckey_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) store_srckey##num
#define store_srccnt_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) store_srccnt##num
#define pkt_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(8) pkt##num

/*for hh*/
 
 #define Action_src_hash(num,algorithm,length)  \
        action SKETCH_src_hash##num() { \
         hash(meta.index_src##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.srcAddr}, (bit<32>)length);\
}
 
 #define Action_srckey_rw(num) \
       action SKETCH_src_rw##num() { \
       store_srckey##num.read(meta.srckey##num, meta.index_src##num); \
       store_srckey##num.write(meta.index_src##num,hdr.ipv4.srcAddr); \
 }

 #define Action_srccnt_incr(num) \
       action SKETCH_srccnt_incr##num() { \
       store_srccnt##num.read(meta.srccnt##num, meta.index_src##num); \
       store_srccnt##num.write(meta.index_src##num,meta.srccnt##num+1); \
 }
 #define Action_srccnt_reset(num) \
       action SKETCH_srccnt_reset##num() { \
       store_srccnt##num.write(meta.index_src##num,0); \
 }

/*ip-pir*/
 #define Action_ip_hash(num,algorithm,length)  \
        action SKETCH_ip_hash##num() { \
         hash(meta.index_ip##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.srcAddr,hdr.ipv4.dstAddr}, (bit<32>)length);\
}
 
 #define Action_ipkey_rw(num) \
       action SKETCH_ip_rw##num() { \
       store_srckey##num.read(meta.srckey##num, meta.index_src##num); \
       store_srckey##num.write(meta.index_src##num,hdr.ipv4.srcAddr); \
 }

 #define Action_srccnt_incr(num) \
       action SKETCH_srccnt_incr##num() { \
       store_srccnt##num.read(meta.srccnt##num, meta.index_src##num); \
       store_srccnt##num.write(meta.index_src##num,meta.srccnt##num+1); \
 }
 #define Action_srccnt_reset(num) \
       action SKETCH_srccnt_reset##num() { \
       store_srccnt##num.write(meta.index_src##num,0); \
 }

 
#define Action_pkt_hit(num) \
        action app_pkt_hit##num(){\
        pkt##num.read(meta.app_pkts_hit##num, meta.app_id);\
        pkt##num.write(meta.app_id,meta.app_pkts_hit##num+1);\
    }

   


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

    register<bit<SKETCH_CELL_BIT_WIDTH>>(1) total_pkts;
    store_srckey_REGISTER(0,SKETCH_BUCKET_LENGTH);
    store_srccnt_REGISTER(0,SKETCH_BUCKET_LENGTH);
    pkt_REGISTER(0)
    Action_srckey_rw(0)
    Action_srccnt_incr(0)
    Action_srccnt_reset(0)
    Action_pkt_hit(0)


    action app_total_pkt(){
        total_pkts.read(meta.app_pkts_total, 0);
        total_pkts.write(0,meta.app_pkts_total+1);
    }
    action drop() {
        mark_to_drop(standard_metadata);
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
  
        
    apply {
        //apply sketch
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
           SKETCH_src_hash0();
           if(meta.srckey0==hdr.ipv4.srcAddr || meta.srckey0==0){
                SKETCH_srccnt_incr(0);
                app_pkt_hit(0);
           }
           else{
                SKETCH_srccnt_reset(0);
           }
           app_total_pkt();    
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
