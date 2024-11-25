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

#define SKETCH_REGISTER(num,length) register<bit<SKETCH_CELL_BIT_WIDTH>>(length) sketch##num
#define pkt_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(1) pkt##num

 
 #define Action_sketch_hash(num,algorithm,length)  \
        action SKETCH_hash##num() { \
         hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.srcAddr, \
 hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)length);\
}
 
 #define Action_sketch_read(num) \
       action SKETCH_COUNT_read##num() { \
 sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
 }
 
 #define Action_sketch_write(num) \
       action SKETCH_COUNT_write##num() {\
       sketch##num.write(meta.index_sketch##num,meta.value_sketch##num+1); \
 }
 
#define Action_read_hit(num) \
        action app_read_hit##num(){\
        pkt##num.read(meta.app_pkts_cnt##num, 0);\
    }
    
#define Action_write_hit(num) \
        action app_write_hit##num(){\
        pkt##num.write(0,meta.app_pkts_cnt##num+1);\
    }
    
#define Table_hit(num) \
     table app_pkts_cnt##num##_tbl { \
     key = {\
            meta.value_sketch##num: exact;\
      }\
        actions = {\
            app_write_hit##num;\
            NoAction;\
        }\
        size = 64;\
        default_action = NoAction;  \
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

    SKETCH_REGISTER(0,SKETCH_BUCKET_LENGTH);
    SKETCH_REGISTER(1,SKETCH_BUCKET_LENGTH);
    SKETCH_REGISTER(2,SKETCH_BUCKET_LENGTH);
    pkt_REGISTER(0);
    pkt_REGISTER(1);
    pkt_REGISTER(2);
    Action_sketch_hash(0,crc32_custom,SKETCH_BUCKET_LENGTH)
    Action_sketch_hash(1,crc32_custom,SKETCH_BUCKET_LENGTH)
    Action_sketch_hash(2,crc32_custom,SKETCH_BUCKET_LENGTH)
    Action_sketch_read(0)
    Action_sketch_read(1) 
    Action_sketch_read(2)  
    Action_sketch_write(0)
    Action_sketch_write(1)  
    Action_sketch_write(2)
    
    Action_read_hit(0)
    Action_write_hit(0)
    Table_hit(0)   
    Action_read_hit(1)
    Action_write_hit(1)
    Table_hit(1) 
    Action_read_hit(2)
    Action_write_hit(2)
    Table_hit(2) 

    SKETCH_REGISTER(3,SKETCH_BUCKET_LENGTH2);
    SKETCH_REGISTER(4,SKETCH_BUCKET_LENGTH2);
    SKETCH_REGISTER(5,SKETCH_BUCKET_LENGTH2);
    pkt_REGISTER(3);
    pkt_REGISTER(4);
    pkt_REGISTER(5);
    Action_sketch_hash(3, crc32_custom,SKETCH_BUCKET_LENGTH2)
    Action_sketch_hash(4,crc32_custom,SKETCH_BUCKET_LENGTH2)
    Action_sketch_hash(5,crc32_custom,SKETCH_BUCKET_LENGTH2)
    Action_sketch_read(3)
    Action_sketch_read(4)
    Action_sketch_read(5)   
    Action_sketch_write(3)
    Action_sketch_write(4) 
    Action_sketch_write(5)
    
    Action_read_hit(3)
    Action_write_hit(3)
    Table_hit(3) 
    Action_read_hit(4)
    Action_write_hit(4)
    Table_hit(4)
    Action_read_hit(5)
    Action_write_hit(5)
    Table_hit(5) 
    
        
    SKETCH_REGISTER(6,SKETCH_BUCKET_LENGTH3);
    SKETCH_REGISTER(7,SKETCH_BUCKET_LENGTH3);
    SKETCH_REGISTER(8,SKETCH_BUCKET_LENGTH3);
    pkt_REGISTER(6);
    pkt_REGISTER(7);
    pkt_REGISTER(8);
    Action_sketch_hash(6, crc32_custom,SKETCH_BUCKET_LENGTH3)
    Action_sketch_hash(7,crc32_custom,SKETCH_BUCKET_LENGTH3)
    Action_sketch_hash(8,crc32_custom,SKETCH_BUCKET_LENGTH3)
    Action_sketch_read(6)
    Action_sketch_read(7)
    Action_sketch_read(8)  
    Action_sketch_write(6)
    Action_sketch_write(7)  
    Action_sketch_write(8)
     
    Action_read_hit(6)
    Action_write_hit(6)
    Table_hit(6) 
    Action_read_hit(7)
    Action_write_hit(7)
    Table_hit(7)
    Action_read_hit(8)
    Action_write_hit(8)
    Table_hit(8) 
   
    
    SKETCH_REGISTER(9,SKETCH_BUCKET_LENGTH4);
    SKETCH_REGISTER(10,SKETCH_BUCKET_LENGTH4);
    SKETCH_REGISTER(11,SKETCH_BUCKET_LENGTH4);
    Action_sketch_hash(9, crc32_custom,SKETCH_BUCKET_LENGTH4)
    Action_sketch_hash(10,crc32_custom,SKETCH_BUCKET_LENGTH4)
    Action_sketch_hash(11,crc32_custom,SKETCH_BUCKET_LENGTH4)
    Action_sketch_read(9)
    Action_sketch_read(10)  
    Action_sketch_read(11)  
    Action_sketch_write(9)
    Action_sketch_write(10)   
    Action_sketch_write(11)
   

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
            SKETCH_hash0();
            SKETCH_hash1();
            SKETCH_hash2();
            SKETCH_hash3();
            SKETCH_hash4();
            SKETCH_hash5();
           // SKETCH_hash6();
           // SKETCH_hash7();
           // SKETCH_hash8();
           // SKETCH_hash9();
           // SKETCH_hash10();
           // SKETCH_hash11();
            
            app_read_hit0();
            SKETCH_COUNT_read0();
            if(meta.app_pkts_cnt0<=SKETCH_BUCKET_LENGTH_fac)
            {
            	SKETCH_COUNT_write0();
            	app_pkts_cnt0_tbl.apply(); 
            }	
            else if(meta.app_pkts_cnt0>SKETCH_BUCKET_LENGTH_fac)
            {
                 app_read_hit3();
                 SKETCH_COUNT_read3();
              //   if(meta.app_pkts_cnt3<SKETCH_BUCKET_LENGTH_fac2)
              //   {
                     SKETCH_COUNT_write3();
                     app_pkts_cnt3_tbl.apply(); 
              //   }
               //  else if(meta.app_pkts_cnt3>=SKETCH_BUCKET_LENGTH_fac2)
               //  {
                 //     app_read_hit6();
                 //     SKETCH_COUNT_read6();
                 //     if(meta.app_pkts_cnt6<SKETCH_BUCKET_LENGTH_fac3)
                 //     {
                 //        SKETCH_COUNT_write6();
                 //        app_pkts_cnt6_tbl.apply();    
                 //     }
                  //    else if(meta.app_pkts_cnt6>=SKETCH_BUCKET_LENGTH_fac3)
                 //     {
                 //         SKETCH_COUNT_write9();
                          //app_pkts_cnt9_tbl.apply(); 
                  //    }
                 
                // }

            }
           
            app_read_hit1();
            SKETCH_COUNT_read1(); 
            if(meta.app_pkts_cnt1<=SKETCH_BUCKET_LENGTH_fac)
            {
            	SKETCH_COUNT_write1();
            	app_pkts_cnt1_tbl.apply(); 
            }	
            else if(meta.app_pkts_cnt1>SKETCH_BUCKET_LENGTH_fac)
            {
                 app_read_hit4();
                 SKETCH_COUNT_read4();
               //  if(meta.app_pkts_cnt4<SKETCH_BUCKET_LENGTH_fac2)
               //  {
                     SKETCH_COUNT_write4();
                     app_pkts_cnt4_tbl.apply(); 
               //  }
               //  else if(meta.app_pkts_cnt4>=SKETCH_BUCKET_LENGTH_fac2)
               //  {
               //       app_read_hit7();
               //       SKETCH_COUNT_read7();
               //       if(meta.app_pkts_cnt7<SKETCH_BUCKET_LENGTH_fac3)
                //      {
                //         SKETCH_COUNT_write7();
                //         app_pkts_cnt7_tbl.apply();    
                //      }
                //      else if(meta.app_pkts_cnt7>=SKETCH_BUCKET_LENGTH_fac3)
                //      {
                //          SKETCH_COUNT_write10();
                 //     }
                 
              //   }

            }
            
            app_read_hit2();
            SKETCH_COUNT_read2();
            if(meta.app_pkts_cnt2<=SKETCH_BUCKET_LENGTH_fac)
            {
            	SKETCH_COUNT_write2();
            	app_pkts_cnt2_tbl.apply(); 
            }	
            else if(meta.app_pkts_cnt2>SKETCH_BUCKET_LENGTH_fac)
            {
                 app_read_hit5();
                 SKETCH_COUNT_read5();
              //   if(meta.app_pkts_cnt5<SKETCH_BUCKET_LENGTH_fac2)
              //   {
                     SKETCH_COUNT_write5();
                     app_pkts_cnt5_tbl.apply(); 
              //   }
               //  else if(meta.app_pkts_cnt5>=SKETCH_BUCKET_LENGTH_fac2)
               //  {
                //      app_read_hit8();
               //       SKETCH_COUNT_read8();
               //       if(meta.app_pkts_cnt8<SKETCH_BUCKET_LENGTH_fac3)
                //      {
                 //        SKETCH_COUNT_write8();
                 //        app_pkts_cnt8_tbl.apply();    
                 //     }
                   //   else if(meta.app_pkts_cnt8>SKETCH_BUCKET_LENGTH_fac3)
                    //  {
                    //      SKETCH_COUNT_write11();
                    //  }
                 
              //   }

            }    
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
