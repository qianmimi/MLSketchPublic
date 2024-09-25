/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> ETHERTYPE_dot1q=0x8100;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;

typedef bit<8>  device_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
header dot1q_t {
  bit<3>  prio;
  bit<1>  activeid;
  bit<12>  vlan;
  bit<16>  type;
}
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


header udp_t {
    bit<16>  srcPort;
    bit<16>  dstPort;
    bit<16>  len;
    bit<16>  hdrChecksum;
}

header FS_h_t {
    bit<16>  ID;
    bit<16>  binid;
    bit<16>  sketchid;
}

header FS_s_t {
    bit<32>  f1;
    bit<32>  f2;
    bit<32>  f3;
    bit<32>  f4;
}

header tcp_t {
    bit<16>  sPort;
    bit<16>  dPort;
    bit<32>  seqNo;
    bit<32>  ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl；
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgentPtr;
}

header udp_t {
    bit<16>  sPort;
    bit<16>  dPort;
    bit<16>  hdr_length;
    bit<16>  checksum;
}

struct headers {
    ethernet_t   ethernet;
    FS_h_t    FS_h;
    FS_s_t    FS_s;
    dot1q_t      dot1q;
    ipv4_t    ipv4;
    tcp_t      tcp；
    udp_t      udp；
}

struct dint_metadata_t {
	bit<32> index;
 	bit<32> index1;
	bit<105> register_value;
	bit<32> srcAddr;
	bit<32> dstAddr;
	bit<16> srcPort;
	bit<16> dstPort;
	bit<8> protocol;
        bit<8> device_no;
  	bit<32> pktnum;
  	bit<32> data;
  	bit<32> data1;
}

struct metadata {
	@name("dint_metadata")
	dint_metadata_t dint_metadata;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
	     ETHERTYPE_dot1q : parse_dot1q;
             0x1000: parse_FS_h;
            default: accept;
        }
    }


   state parse_FS_h {
        packet.extract(hdr.FS_h);
        transition parse_FS_s;
    }

   state parse_FS_s {
        packet.extract(hdr.FS_s);
        transition parse_dot1q;
    }

	// Dot1Q.
   state parse_dot1q {
    	packet.extract(hdr.dot1q);
    	transition parse_ipv4;
     }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            17: parse_udp;
            default: accept;
        }  
    }    
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
    @name("drop")
    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action setdeviceno(bit<8> device_no) {
         meta.dint_metadata.deviceno=device_no;
    }
    table deviceno_tbl {
	  actions = {
	    setdeviceno;
            drop;
            NoAction;
          }
	  key = {}
	  size = 1024;
          default_action = drop();
     }
    
     apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            deviceno_tbl.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
	// 256 KB space: 104-bit flowkey, 8-bit deviceno, 1-bit ID, 32-bit time, 19-bit depth_constant1, 4-bit depth_m1, 19-bit depth_constant2, 4-bit depth_m2
	register<bit<32>>(65536) fs_a_1_1;
	register<bit<32>>(65536) fs_a_1_2;
  
	register<bit<32>>(65536) fs_b_1_1;
 	register<bit<32>>(65536) fs_b_1_2;

        register<bit<32>>(1) colum;


 
  	@name("tcp_hash")
 	action tcp_hash() {
		hash(meta.dint_metadata.index, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, 32w65536);
	}
  	@name("ipv4_hash")
 	action ipv4_hash() {
		hash(meta.dint_metadata.index, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 32w65536);
	}

 	@name("tcp_hash_tbl")
	table tcp_hash_tbl {
		actions = {
			tcp_hash;
		}
		key = {}
		size = 1024;
		default_action = tcp_hash();
	}
 	@name("ipv4_hash_tbl")
	table ipv4_hash_tbl {
		actions = {
			ipv4_hash;
		}
		key = {}
		size = 1024;
		default_action = ipv4_hash();
	}




       @name("udp_hash")
	action udp_hash() {
		hash(meta.dint_metadata.index, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol}, 32w65536);
	}
 	action udp_hash1() {
		hash(meta.dint_metadata.index1, HashAlgorithm.crc16, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol}, 32w65536);
	}
 
	@name("udp_hash_tbl")
	table udp_hash_tbl {
		actions = {
			udp_hash;
		}
		key = {}
		size = 1024;
		default_action = udp_hash();
	}
 	@name("udp_hash_tbl1")
	table udp_hash_tbl1 {
		actions = {
			udp_hash1;
		}
		key = {}
		size = 1024;
		default_action = udp_hash1();
	}
       @name("read_register")
	action read_register() {
		fs_a_1_1.read(meta.dint_metadata.register_value, meta.dint_metadata.index);
		fs_a_1_2.read(meta.dint_metadata.register_value1, meta.dint_metadata.index1);
                colum.read(meta.dint_metadata.pktnum, 0);
	}
	@name("read_register_tbl")
	table read_register_tbl {
		actions = {
			read_register;
		}
		key = {}
		size = 1024;
		default_action = read_register();
	}
       @name("read_register_b")
	action read_register_b() {
		fs_b_1_1.read(meta.dint_metadata.register_value, meta.dint_metadata.index);
		fs_b_1_2.read(meta.dint_metadata.register_value1, meta.dint_metadata.index1);
                colum.read(meta.dint_metadata.pktnum, 0);
	}
	@name("read_register_tbl_b")
	table read_register_tbl_b {
		actions = {
			read_register_b;
		}
		key = {}
		size = 1024;
		default_action = read_register_b();
	}

       @name("insert_data")
	action insert_data() {
		fs_a_1_1.read(meta.dint_metadata.data, meta.dint_metadata.pktnum);
		fs_a_1_2.read(meta.dint_metadata.data1, meta.dint_metadata.pktnum);
		fs_a_1_1.write(meta.dint_metadata.pktnum,0);
		fs_a_1_2.write(meta.dint_metadata.pktnum,0);
	}
	@name("insert_data_tbl")
	table insert_data_tbl {
		actions = {
			insert_data;
		}
		key = {}
		size = 1024;
		default_action = insert_data();
	}

       @name("insert_data")
	action insert_data_b() {
		fs_b_1_1.read(meta.dint_metadata.data, meta.dint_metadata.pktnum);
		fs_b_1_2.read(meta.dint_metadata.data1, meta.dint_metadata.pktnum);
		fs_b_1_1.write(meta.dint_metadata.pktnum,0);
		fs_b_1_2.write(meta.dint_metadata.pktnum,0);
	}
	@name("insert_data_tbl")
	table insert_data_tbl_b {
		actions = {
			insert_data_b;
		}
		key = {}
		size = 1024;
		default_action = insert_data_b();
	}
	action insert_FS_h() {
		hdr.FS_h.setValid();
		hdr.FS_h.binid = meta.dint_metadata.pktnum;
		hdr.FS_h.sketchid = hdr.dot1q.prio;
		hdr.FS_h.ID = meta.dint_metadata.deviceno;
		//hdr.udp.len = hdr.udp.len+16w6;
		//hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w6;
		//hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w6;
	}
	table do_FS_h_tbl {
		actions = {
			insert_FS_h;
		}
		key = {}
		size = 1024;
		default_action = insert_FS_h();
	}

 	action insert_FS_s_1() {
		hdr.FS_s.setValid();
		hdr.FS_s.f1 = meta.dint_metadata.register_value;
		hdr.FS_s.f2 = meta.dint_metadata.register_value1;
		hdr.FS_h.ID = meta.dint_metadata.deviceno;
		//hdr.udp.len = hdr.udp.len+16w16;
		//hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w16;
		//hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w16;
	}
	table do_FS_s_tbl_1 {
		actions = {
			insert_FS_s_1;
		}
		key = {}
		size = 1024;
		default_action = insert_FS_s_1();
	}

 	action insert_FS_s_2() {
		hdr.FS_s.setValid();
		hdr.FS_s.f3 = meta.dint_metadata.register_value;
		hdr.FS_s.f4 = meta.dint_metadata.register_value1;
		hdr.FS_h.ID = meta.dint_metadata.deviceno;
		//hdr.udp.len = hdr.udp.len+16w16;
		//hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w16;
		//hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w16;
	}
	table do_FS_s_tbl_2 {
		actions = {
			insert_FS_s_2;
		}
		key = {}
		size = 1024;
		default_action = insert_FS_s_2();
	}

	action update_register() {
  		fs_a_1_1.write(meta.dint_metadata.index, meta.dint_metadata.register_value+1);
  		fs_a_1_2.write(meta.dint_metadata.index1, meta.dint_metadata.register_value1+1);
	}
	table update_register_tbl {
		actions = {
			update_register;
		}
		key = {}
		size = 1024;
		default_action = update_register();
	}

	action update_register_b() {
  		fs_b_1_1.write(meta.dint_metadata.index, meta.dint_metadata.register_value+1);
  		fs_b_1_2.write(meta.dint_metadata.index1, meta.dint_metadata.register_value1+1);
	}
	table update_register_tbl_b {
		actions = {
			update_register_b;
		}
		key = {}
		size = 1024;
		default_action = update_register_b();
	}

	action update_regpktnum() {
                colum.write(0,meta.dint_metadata.pktnum+1);
	}
	table update_regpktnum_tb {
		actions = {
			update_regpktnum;
		}
		key = {}
		size = 1024;
		default_action = update_regpktnum();
	}


        apply{
	        udp_hash_tbl.apply();
		udp_hash_tbl1.apply();
		if(hdr.dot1q.prio==0){   //标志位为0，初始状态
		   read_register_tbl.apply();
		   update_register_tbl.apply();
		}
                else if(hdr.dot1q.prio==1){ //标志为1，收集第一个sketch数据，更新第二个（b结尾的）sketch数据
		    read_register_tbl_b.apply();
                    if(0<=meta.dint_metadata.pktnum<65536) //收集完全部数据后不再收集，等待标志位2
			{
			   insert_data_tbl.apply();
			    do_FS_h_tbl.apply();
		           if(meta.dint_metadata.deviceno==1){
			      do_FS_s_tbl_1.apply();  //第一台交换机的数据
		           }
		          else{
                              do_FS_s_tbl_2.apply(); //第二台交换机的数据
		          } 
			update_regpktnum_tb.apply(); //更新计数器
		    }
		   update_register_tbl_b.apply();
               }
	     else {
		   read_register_tbl.apply();
                    if(0<=meta.dint_metadata.pktnum<65536)
			{
			   insert_data_tbl_b.apply();
			    do_FS_h_tbl.apply();
		           if(meta.dint_metadata.deviceno==1){
			      do_FS_s_tbl_1.apply();
		           }
		           else{
                              do_FS_s_tbl_2.apply();
		          } 
			update_regpktnum_tb.apply();
		    }
		   update_register_tbl.apply();
	     }
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.FS_h);
        packet.emit(hdr.FS_s);
        packet.emit(hdr.dot1q);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
