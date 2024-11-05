/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 28
#define SKETCH_CELL_BIT_WIDTH 32
#define slotSize 16384 //2的14次方




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
    register<bit<16>>(1) gmrPointer;
    register<bit<16>>(SKETCH_BUCKET_LENGTH) slotPointer;
    register<bit<64>>(SKETCH_BUCKET_LENGTH) pageTable;
    register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch1;
    register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch2;
    register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch3;




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
   action set_app_para(bit<16> width_bit, bit<8> type, bit<32> app_id,bit<16> width){
        meta.width_bit = width_bit;
        meta.width = width;
        meta.type = type;
        meta.app_id = app_id;
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
       hash(meta.output_hash_one, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                          hdr.ipv4.dstAddr,
                                                          hdr.tcp.srcPort,
                                                          hdr.tcp.dstPort,
                                                          hdr.ipv4.protocol},
                                                          (bit<32>)SKETCH_BUCKET_LENGTH);

       hash(meta.output_hash_two, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                          hdr.ipv4.dstAddr,
                                                          hdr.tcp.srcPort,
                                                          hdr.tcp.dstPort,
                                                          hdr.ipv4.protocol},
                                                          (bit<32>)SKETCH_BUCKET_LENGTH);
}
   action read_pagetbl_act(){ //num用幂次方来表示，初始值为0,1,2,3...
        pageTable.read(meta.addr, meta.app_id);
	meta.voff=(bit<32>)(meta.addr>>32);
	meta.hoff=(bit<16>)((meta.addr >> 16) & 0xffff);
	meta.bnum=(bit<8>)(meta.addr & 0xffff);
    }

    table read_pagetbl_tbl {
        actions = {
            read_pagetbl_act;
        }
    }




//转换，stageID=hoff>>5+1; pa=(h(*)<<bnum)%16384+voff; pval=(h(*)<<bnum)/16384*widthbit+hoff%b

   action transfer_addr_act(){ 
	meta.stage_ID=meta.hoff>>5+1;
	meta.paddr=((meta.output_hash_one << meta.bnum) & 0x3FFF) + meta.voff;
	meta.pval=((meta.output_hash_one << meta.bnum) >> 14)<<meta.width_bit + meta.hoff&31;
    }

  table transfer_addr_tbl {
        actions = {
            transfer_addr_act;
        }
    }
   action operator_tarval_act(){ 
	meta.mask=(bit<32>)1<<(32-meta.pval+(bit<32>)meta.width_bit);
     }
    table operator_tarval_tbl {
	//key = {
         //   meta.width_bit: exact;//可能是1，8，16，32;
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
         sketch1.read(meta.value_sketch, meta.paddr);
         meta.value_sketch = meta.value_sketch | meta.mask;
         sketch1.write(meta.paddr, meta.value_sketch);
    }

    table Update_register_tbl1 {
        key = {
            meta.stage_ID: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            Update_register_act1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
   action Update_register_act2(){
         sketch2.read(meta.value_sketch, meta.paddr);
         meta.value_sketch = meta.value_sketch | meta.mask;
         sketch2.write(meta.paddr,meta.value_sketch);
    }

    table Update_register_tbl2 {
        key = {
            meta.stage_ID: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            Update_register_act2;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action Update_register_act3(){
         sketch3.read(meta.value_sketch, meta.paddr);
         meta.value_sketch = meta.value_sketch |meta.mask;
         sketch3.write(meta.paddr,meta.value_sketch);
    }

    table Update_register_tbl3 {
        key = {
            meta.stage_ID: exact; //不同的ingress_port对应不同的app_id
        }
        actions = {
            Update_register_act3;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action app_rpkts_cnt_num(){
        app_pkts_cnt.read(meta.app_pkts_cnt, meta.app_id);
    }
   action app_rwpkts_cnt_num(){
        app_pkts_cnt.read(meta.app_pkts_cnt, meta.app_id);
	//if(meta.value_sketch==0){
	     meta.app_pkts_cnt = meta.app_pkts_cnt + 1;
             app_pkts_cnt.write(meta.app_id,meta.app_pkts_cnt);
	//}
    }

    table app_pkts_cnt_tbl {
     key = {
            meta.value_sketch: exact;
      }
        actions = {
            app_rpkts_cnt_num;
            app_rwpkts_cnt_num;
            NoAction;
        }
         size = 64;
        default_action = NoAction;  
    }

   action load_factor_act1(){
	meta.allocFlag=1;
    }
   action load_factor_act0(){
	meta.allocFlag=0;
    }

    table Load_factor_tbl {
        key = {
            meta.bnum: exact;
	    meta.app_pkts_cnt:range;
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
        gmrPointer.read(meta.slotID, (bit<32>)0);
	meta.slotID=meta.slotID+1;
        gmrPointer.write(0, meta.slotID);
    }

    table read_gmrPointer_tbl {
        key = {
	    meta.allocFlag: exact;
        }
        actions = {
            read_gmrPointer;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
   action set_partition_block(bit<16> hstart, bit<16> hend, bit<32> voff){
        meta.hstart = hstart;
        meta.hend = hend;
        meta.voff = voff;
    }

    table parti_tbl {
        key = {
            meta.slotID: exact; 
	    meta.allocFlag: exact;
        }
        actions = {
            set_partition_block;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

   action allocread_slotIDhPos(){
	//slotIDhPos<=hend-wide
        slotPointer.read(meta.slotIDhPos, (bit<32>)meta.slotID);

    }
  
    table read_slotIDhPos_tbl {
        key = {
	    meta.allocFlag: exact;
	    meta.hend: exact;//这个end，由于每个空闲分区表都知道它的end
	    meta.width:exact;//1，8，16，32
	    
        }
        actions = {
            allocread_slotIDhPos;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
    action allocwrite_slotIDhPos(){
	//slotIDhPos<=hend-wide
	meta.slotIDhPos=meta.slotIDhPos+meta.width;
	meta.nvoff=meta.voff;
	meta.nhoff=meta.slotIDhPos;
	slotPointer.write((bit<32>)meta.slotID,meta.slotIDhPos);
	meta.sucess=1;
    }
  
    table write_slotIDhPos_tbl {
        key = {
	    meta.allocFlag: exact;
	    meta.hend: exact;//这个end，由于每个空闲分区表都知道它的end
	    meta.width:exact;//1，8，16，32
	    
        }
        actions = {
            allocwrite_slotIDhPos;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
    
    
    action clone_forupdate_act(){
	meta.addr=((bit<64>)meta.nvoff<<32)| ((bit<64>)meta.nhoff<<16) | ((bit<64>)meta.bnum<<1);
	clone_preserving_field_list(CloneType.I2E, 5, CLONE_FL_1);
    }

    table clone_forupdate_tbl {
        key = {
	    meta.sucess: exact;
        }
        actions = {
            clone_forupdate_act;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
       action write_pagetbl_act(){ //num用幂次方来表示，初始值为0,1,2,3...
        pageTable.write(meta.app_id,meta.addr);
    }

    table write_pagetbl_tbl {
        actions = {
            write_pagetbl_act;
        }
    }
    action app_reset_hit_num(){
        app_pkts_cnt.write(meta.app_id,0);
    }

    table app_reset_hit_tbl {
        actions = {
            app_reset_hit_num;
        }
    }

    apply {
        //apply sketch，还有旧的hash位置地址还没发给控制器
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
	    init_tbl.apply();//初始化
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
	    if(meta.slotIDhPos+meta.width<meta.hend){
		 write_slotIDhPos_tbl.apply();
            }
	    clone_forupdate_tbl.apply();//clone数据包,去更新page table
	  }
	  else{
	    write_pagetbl_tbl.apply();//更新寄存器
	    app_reset_hit_tbl.apply();//重置hit_num
	  
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
   
    apply { 

   }
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
