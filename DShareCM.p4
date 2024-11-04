/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 28
#define SKETCH_CELL_BIT_WIDTH 64
#define slotSize 1024

const bit<8> EMPTY_FL    = 0;
const bit<8> RESUB_FL_1  = 1;
const bit<8> CLONE_FL_1  = 2;
const bit<8> RECIRC_FL_1 = 3;

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
header meta_t {
    @field_list(CLONE_FL_1)
    bit<64>  addr;
}

struct metadata_t {
    share_metadata_t share_metadata;
    meta_t meta;
};


#define SKETCH_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch##num


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
    register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) pageTable;

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

   action app_pkts_cnt_num(){
        app_pkts_cnt.read(share_metadata.app_pkts_cnt, share_metadata.app_id);
        share_metadata.app_pkts_cnt = share_metadata.app_pkts_cnt + 1;
        app_pkts_cnt.write(share_metadata.app_id,share_metadata.app_pkts_cnt);
    }

    table app_pkts_cnt_tbl {
        actions = {
            app_pkts_cnt_num;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action app_miss_cnt_num(){
        app_miss_cnt.read(share_metadata.app_miss_cnt, share_metadata.app_id);
        share_metadata.app_miss_cnt = share_metadata.app_miss_cnt + 1;
        app_miss_cnt.write(share_metadata.app_id,share_metadata.app_miss_cnt);
    }

    table app_miss_cnt_tbl {
        actions = {
            app_miss_cnt_num;
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

   action read_slotIDhPos(){
        slotPointer.read(share_metadata.hPos, share_metadata.gmrPointer);
    }

    table read_slotIDhPos_tbl {
        actions = {
            read_slotIDhPos;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

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

   action update_page_act(){
        pageTable.read(meta.addr, share_metadata.app_id);
        pageTable.write(share_metadata.app_id,(bit<32>)share_metadata.hoff&&(bit<32>)(32<<share_metadata.voff));
    }

    table Update_page_tbl {
        actions = {
            update_page_act;
        }
    }

   action Read_page_act(){
        pageTable.read(meta.addr, share_metadata.app_id);
    }

    table Read_page_tbl {
        actions = {
            Read_page_act;
        }
    }

   action Get_stageID_act(){
        share_metadata.stageID=share_metadata.hoff>>5+1;
    }

    table Get_stageID_tbl {
        actions = {
            Get_stageID_act;
        }
    }

   action Get_vaddr_act(){
        share_metadata.vaddr=share_metadata.hash_out%slotSize+voff;
    }

    table Get_vaddr_tbl {
        actions = {
            Get_vaddr_act;
        }
    }

   action Get_haddr_act(){
        share_metadata.haddr=share_metadata.hoff%32;
    }

    table Get_haddr_tbl {
        actions = {
            Get_haddr_act;
        }
    }

   action Operator_value_act(bit<32> mask){
        share_metadata.val=1&mask;
    }

    table Operator_value_tbl {
        key = {
            share_metadata.haddr: range; 
        }
        actions = {
            Operator_value_act;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
   action Update_register_act1(){
         sketch1.read(meta.value_sketch1, share_metadata.vaddr);
         meta.value_sketch1 = meta.value_sketch1 +share_metadata.val;
         sketch1.write(share_metadata.vaddr meta.value_sketch1)
    }

    table Update_register_tbl1 {
        key = {
            standard_metadata.stage_ID: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            Update_register_act1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
   action Update_register_act2(){
         sketch2.read(meta.value_sketch2, share_metadata.vaddr);
         meta.value_sketch2 = meta.value_sketch2 +share_metadata.val;
         sketch1.write(share_metadata.vaddr meta.value_sketch2)
    }

    table Update_register_tbl2 {
        key = {
            standard_metadata.stage_ID: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            Update_register_act2;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action Update_register_act3(){
         sketch1.read(meta.value_sketch3, share_metadata.vaddr);
         meta.value_sketch3 = meta.value_sketch3 +share_metadata.val;
         sketch1.write(share_metadata.vaddr meta.value_sketch3)
    }

    table Update_register_tbl3 {
        key = {
            standard_metadata.stage_ID: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            Update_register_act3;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

action do_copy_to_cpu() {
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, mirror_list_1);
}
table copy_to_cpu {
        key = {
            standard_metadata.stage_ID: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            do_copy_to_cpu;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
action do_clone_header() {
    clone_header.addr=standard_metadata.add;
    add_header(clone_header);
}
table ticlone {
        key = {
           standard_metadata.instance_type: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            do_copy_to_cpu;
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
        read_slotIDhPos_tbl.apply();
        read_gmrPointer_tbl.apply();
        if((share_metadata.pkts_total_cnt-5)%Count==0&&share_metadata.allocFlag==0){ //内存分配
        if(share_metadata.hPos+share_metadata.width<share_metadata.hend){
            if(share_metadata.hPos%32<width){
                share_metadata.hPos=(share_metadata.hPos>>5+1)<<5;
            }
        }
        share_metadata.hoff=share_metadata.hPos;
        Update_page_tbl.apply();
       }
        else{//直接读取页表
            Read_page_tbl.apply();
        }
        Get_stageID_tbl.apply();
        Get_vaddr_tbl.apply();
        Get_haddr_tbl.apply();
        Operator_value_tbl.apply();
        Update_register_tbl3.apply();
        Update_register_tbl2.apply();
        Update_register_tbl1.apply();
        
        if(standard_metadata.instance_type == 0){
    		copy_to_cpu.apply();
	   }
        else{
          ticlone.apply();  
        }
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
