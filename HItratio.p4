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
#define pkt_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(8) pkt_hit##num

#define store_ip_src_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) store_ip_srckey##num
#define store_ip_dst_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) store_ip_dstkey##num

#define store_tuple_src_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) store_tuple_srckey##num
#define store_tuple_dst_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) store_tuple_dstkey##num
#define store_tuple_srcport_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) store_tuple_dstportkey##num
#define store_tuple_dstport_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) store_tuple_dstportkey##num



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
 #define Action_ip_src_rw(num) \
       action SKETCH_ip_src_rw##num() { \
       store_ip_srckey##num.read(meta.ipkey_src##num, meta.index_ip##num); \
       store_ip_srckey##num.write(meta.index_ip##num, hdr.ipv4.srcAddr); \
 }
 #define Action_ip_dst_rw(num) \
       action SKETCH_ip_dst_rw##num() { \
       store_ip_dstkey##num.read(meta.ipkey_dst##num, meta.index_ip##num); \
       store_ip_dstkey##num.write(meta.index_ip##num, hdr.ipv4.dstAddr); \
 }

//for turboflow
 #define Action_tuple_hash(num,algorithm,length)  \
         action SKETCH_tuple_hash##num() { \
         hash(meta.index_tuple##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.srcAddr, \
 hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)length);\
 }
 #define Action_tuple_src_rw(num) \
       action SKETCH_tuple_src_rw##num() { \
       store_tuple_srckey##num.read(meta.tuplekey_src##num, meta.index_tuple##num); \
       store_tuple_srckey##num.write(meta.index_tuple##num, hdr.ipv4.srcAddr); \
 }
 #define Action_tuple_dst_rw(num) \
       action SKETCH_tuple_dst_rw##num() { \
       store_tuple_dstkey##num.read(meta.tuplekey_dst##num, meta.index_tuple##num); \
       store_tuple_dstkey##num.write(meta.index_tuple##num, hdr.ipv4.dstAddr); \
 }
 #define Action_tuple_srcport_rw(num) \
       action SKETCH_tuple_srcport_rw##num() { \
       store_tuple_srcportkey##num.read(meta.tuplekey_srcport##num, meta.index_tuple##num); \
       store_tuple_srcportkey##num.write(meta.index_tuple##num, hdr.tcp.srcPort); \
 }
 #define Action_tuple_dstport_rw(num) \
       action SKETCH_tuple_dstport_rw##num() { \
       store_tuple_dstportkey##num.read(meta.tuplekey_dst##num, meta.index_tuple##num); \
       store_tuple_dstportkey##num.write(meta.index_tuple##num, hdr.tcp.dstPort); \
 }

 #define Action_pkt_hit(num,appid) \
       action app_pkt_hit##num() { \
       pkt_hit##num.read(meta.hit_cnt##num, appid); \
       pkt_hit##num.write(appid,meta.hit_cnt##num+1); \
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
    Action_pkt_hit(0,1)
     

  //for ip-pair
    Action_ip_hash(0)
    store_ip_dst_REGISTER(0)
    store_ip_src_REGISTER(0)
    Action_pkt_hit(1,2)


//for turblflow
   Action_tuple_hash(0)
   Action_tuple_src_rw(0)
   Action_tuple_dst_rw(0)
   Action_tuple_srcport_rw(0)
   Action_tuple_dstport_rw(0)
   Action_pkt_hit(2,3)





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
           SKETCH_src_hash0()
           SKETCH_src_rw0()
           if(meta.srckey0==hdr.ipv4.srcAddr || meta.srckey0==0){
                SKETCH_srccnt_incr(0)
                app_pkt_hit0
           }
           else{
                SKETCH_srccnt_reset(0)
           }   
        }
          //for ip-pair 
          SKETCH_ip_hash0()
          SKETCH_ip_src_rw(0)
          SKETCH_ip_dst_rw(0)
          if((meta.ipkey_src0==hdr.ipv4.srcAddr && meta.ipkey_dst0==hdr.ipv4.dstAddr) && ( meta.ipkey_src0==0 && meta.ipkey_dst0==0)){
              app_pkt_hit1
          }

         //for turboflow
          



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
