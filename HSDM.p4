/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 28
#define SKETCH_CELL_BIT_WIDTH 64
#define slotSize 16384 //2的14次方

header share_metadata_t {
    bit<8> output_hash_one;
    bit<8> output_hash_two;
    bit<8> width;
    bit<8> type;
    bit<32> voff;
    bit<16> hoff;
    bit<16> bnum;
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


#define SKETCH_COUNT(num, algorithm) hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.srcAddr, \
 hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)SKETCH_BUCKET_LENGTH);\
 sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
 meta.value_sketch##num = meta.value_sketch##num +1; \
 sketch##num.(meta.index_sketch##num, meta.value_sketch##num)

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
   action set_app_para(bit<8> width_bit, bit<8> type, bit<8> app_id){
        share_metadata.width_bit = width_bit;
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


action Calc_hash(){
       //Get hash out
       hash(share_metadata.output_hash_one, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                          hdr.ipv4.dstAddr,
                                                          hdr.tcp.srcPort,
                                                          hdr.tcp.dstPort,
                                                          hdr.ipv4.protocol},
                                                          (bit<32>)SKETCH_BUCKET_LENGTH);

       hash(share_metadata.output_hash_two, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                          hdr.ipv4.dstAddr,
                                                          hdr.tcp.srcPort,
                                                          hdr.tcp.dstPort,
                                                          hdr.ipv4.protocol},
                                                          (bit<32>)SKETCH_BUCKET_LENGTH);
}
   action read_pagetbl_act(){ //num用幂次方来表示，初始值为0,1,2,3...
        pageTable.read(share_metadata.addr, share_metadata.app_id);
	share_metadata.voff=(bit<32>)share_metadata.addr>>32;
	share_metadata.hoff=(bit<16>)(share_metadata.addr >> 16) & 0xffff;
	share_metadata.bnum=(bit<16>) share_metadata.addr & 0xffff;
    }

    table read_pagetbl_tbl {
        actions = {
            read_pagetbl_act;
        }
    }

   action write_pagetbl_act(){ //num用幂次方来表示，初始值为0,1,2,3...
        pageTable.write(share_metadata.app_id,share_metadata.addr);
    }

    table write_pagetbl_tbl {
        actions = {
            write_pagetbl_act;
        }
    }


//转换，stageID=hoff>>5+1; pa=(h(*)<<bnum)%16384+voff; pval=(h(*)<<bnum)/16384*widthbit+hoff%b

   action transfer_addr_act(){ 
	share_metadata.stageID=share_metadata.hoff>>5+1;
	share_metadata.paddr=((share_metadata.output_hash_one << share_metadata.bnum) & 0x3FFF) + share_metadata.voff;
	share_metadata.pval=((share_metadata.output_hash_one << share_metadata.bnum) << 14)>>width_bit + share_metadata.hoff&31;
    }

  table transfer_addr_tbl {
        actions = {
            transfer_addr_act;
        }
    }
   action operator_tarval_act(){ 
	share_metadata.mask=bit<32>(1<<(32-share_metadata.pval+share_metadata.width_bit));
     }
    table operator_tarval_tbl {
	//key = {
         //   share_metadata.width_bit: exact;//可能是1，8，16，32;
      //  }
        actions = {
            operator_tarval_act;
           // drop;
            //NoAction;
        }
    //    size = 64;
     //   default_action = drop;
    }
   action Update_register_act1(){
         sketch1.read(share_metadata.value_sketch, share_metadata.paddr);
         share_metadata.value_sketch = share_metadata.value_sketch | share_metadata.mask;
         sketch1.(share_metadata.paddr, share_metadata.value_sketch);
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
         sketch2.read(share_metadata.value_sketch, share_metadata.paddr);
         share_metadata.value_sketch = share_metadata.value_sketch | share_metadata.mask;
         sketch2.(share_metadata.paddr,share_metadata.value_sketch);
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
         sketch3.read(share_metadata.value_sketch, share_metadata.paddr);
         share_metadata.value_sketch = share_metadata.value_sketch | share_metadata.mask;
         sketch3.(share_metadata.paddr,share_metadata.value_sketch);
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

   action app_pkts_cnt_num(){
        app_pkts_cnt.read(share_metadata.app_pkts_cnt, share_metadata.app_id);
	if(share_metadata.value_sketch==0){
	     share_metadata.app_pkts_cnt = share_metadata.app_pkts_cnt + 1;
             app_pkts_cnt.(share_metadata.app_id,share_metadata.app_pkts_cnt);
	}
    }

    table app_pkts_cnt_tbl {
        actions = {
            app_pkts_cnt_num;
        }
    }
   action app_reset_hit_num(){
        app_pkts_cnt.(share_metadata.app_id,0);
    }

    table app_reset_hit_tbl {
        actions = {
            app_reset_hit_num;
        }
    }

   action load_factor_act1(){
	share_metadata.allocFlag=1;
    }
   action load_factor_act0(){
	share_metadata.allocFlag=0;
    }

    table Load_factor_tbl {
        key = {
            share_metadata.bnum: exact;
	    share_metadata.app_pkts_cnt:range;
        }
        actions = {
            load_factor_act0;
	    load_factor_act1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action read_gmrPointer(){
        gmrPointer.read(share_metadata.slotID, 0);
	share_metadata.slotID=share_metadata.slotID+1;
        gmrPointer.read(0, share_metadata.slotID);
    }

    table read_gmrPointer_tbl {
        key = {
	    share_metadata.allocFlag: exact;
        }
        actions = {
            read_gmrPointer;
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
	    share_metadata.allocFlag: exact;
        }
        actions = {
            set_partition_block;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action allocsuc_slotIDhPos(){
	//slotIDhPos<=hend-wide
        slotPointer.read(share_metadata.slotIDhPos, share_metadata.slotID);
	if(share_metadata.slotIDhPos+share_metadata.wide<share_metadata.hend){
	share_metadata.slotIDhPos=share_metadata.slotIDhPos+share_metadata.wide;
	share_metadata.nvoff=share_metadata.voff;
	share_metadata.nhoff=share_metadata.slotIDhPos;
	slotPointer.(share_metadata.slotID,share_metadata.slotIDhPos);
	share_metadata.sucess=1;
	}
    }

    table read_slotIDhPos_tbl {
        key = {
	    share_metadata.allocFlag: exact;
	    share_metadata.hend: exact;//这个end，由于每个空闲分区表都知道它的end
	    share_metadata.wide:exact;//1，8，16，32
	    
        }
        actions = {
            read_slotIDhPos;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   #define CPU_MIRROR_SESSION_ID                  250
    field_list mirror_list_1 {   
        share_metadata.addr;
	share_metadata.app_id;
   }
   action clone_forupdate_act(){
	share_metadata.addr=(share_metadata.nvoff<<32)| (share_metadata.nhoff<<16) | (share_metadata.bnum<<1);
	clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, mirror_list_1);
    }

    table clone_forupdate_tbl {
        key = {
	    share_metadata.sucess: exact;
        }
        actions = {
            clone_forupdate_act;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }


    apply {
        //apply sketch
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
	    init_tbl.apply();初始化
	    Calc_hash();//计算hash
	    if(standard_metadata.instance_type==0){
	    read_pagetbl_tbl.apply();//读取地址
	    transfer_addr_tbl.apply(); //转化地址，获取register访问地址;
	    operator_tarval_tbl.apply();//获得mask
	    Update_register_tbl1.apply();//更新寄存器
	    Update_register_tbl2.apply();
            Update_register_tbl3.apply();
            app_pkts_cnt_tbl.apply();//累计hit_cnt；
	    Load_factor_tbl.apply();//加载负载因子;
	    read_gmrPointer_tbl.apply();//读取GMR当前的环形执行,得到当前slotID
	    parti_tbl.apply();//读取空闲分区表
	    read_slotIDhPos_tbl.apply();//分配
	    clone_forupdate_tbl.apply();//clone数据包,去更新page table
	  }
	   else{  //克隆包
		write_pagetbl_tbl.apply();更新寄存器
		app_reset_hit_tbl.apply();重置hit_num

	   }
         //sketch_count();
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
