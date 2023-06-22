
#
# Defined types for the ISO over TCP / S7Comm analyzer
# 
# Author: Dane Wullen
# Date: 10.04.2018
# Version: 1.0
# 
# This plugin is a part of a master's thesis written at Fachhochschule in Aachen (Aachen University of Applied Sciences)
# 
#

module S7Comm;

export {

	type S7Header: record {
		protocol_id:	count;
		msg_type:		count;
		pdu_ref:		count;
		param_length:	count;
		data_length:	count;
		error_class:	count;
		error_code:		count;
	};
	
	type S7SetupCommParam: record {
		maxamqcaller:	count;
		maxamqcalling:	count;
		pdulength:		count;
	};

	
	type S7AnyTypeItem: record {
		transportsize:	count;
		length:			count;
		dbnumber:		count;
		area:			count;
		byte_offset:	count;
		bit_offset:		count;
		address:		string;
	};

	type S7DBTypeSubitem: record {
		bytestoread:	count;
		dbnumber:		count;
		startaddress:	count;
	};
	type S7DBTypeItem: record {
		numberofarea:	count;
		subitems:		vector of S7DBTypeSubitem;
	};

	type S71200SymSubstructurItem: record {
		lid_flag:		count;
		value:			count;
	};
	type S71200SymTypeItem: record {
		reserved:		count;
		rootarea1:		count;
		rootarea2:		count;
		crc:			count;
		substructure: 	vector of S71200SymSubstructurItem;
	};

	type S7NCKTypeItem: record {
		area:			count;
		unit:			count;
		column:			count;
		line:			count;
		nckmodule:		count;
		linecount:		count;
	};

	type S7DriveAnyTypeItem: record {
		nr:				count;
		idx:			count;
	};

	type S7ReadWriteData: record {
		error_code:		count;
		transport_size: count;
		length:			count;
		data:			string;
	};

	type S7JobStartUpload: record {
		func_status:		count;
		upload_id:			count;
		filename_length:	count;
		filename:			string;
	};

	type S7AckDataStartUpload: record {
		func_status:				count;
		upload_id:					count;
		blocklength_string_length:	count;
		blocklength:				string;
	};

	type S7JobRequestDownload: record {
		func_status:		count;
		filename_length:	count;
		filename:			string;
		length_load_memory:	count;
		length_mc7_code:	count;
	};

	type S7JobDownloadBlock: record {
		func_status:		count;
		filename_length:	count;
		filename:			string;
	};

	type S7AckDataDownloadBlock: record {
		data_length:		count;
		data:				string;
	};

	type S7JobDownloadEnded: record {
		func_status: 		count;
		error_code:			count;
		filename_length:	count;
		filename:			string;
	};

	type S7JobPLCControlBlock: record {
		param_block_length:	count;
	};

	type S7AnyTypeVector:	    		vector of S7AnyTypeItem;
	type S7DBTypeVector:	    		vector of S7DBTypeItem;
	type S7DBTypeSubitemVector:			vector of S7DBTypeSubitem;
	type S71200SymTypeVector:   		vector of S71200SymTypeItem;
	type S71200SymSubstructurVector:    vector of S71200SymSubstructurItem;
	type S7NCKTypeVector:               vector of S7NCKTypeItem;
	type S7DriveESAnyTypeVector:        vector of S7DriveAnyTypeItem;


	###### UserData Types ######

	## Unknown Data

	type S7UDUnknownData: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		data:				string;
	};

	## Function Group Programmer commands
	type S7UDReqDiagItem: record {
		address:	int;
		registers: 	count;
	};

	type S7UDReqDiagData: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		ask_header_size:	count;
		ask_size:			count;
		answer_size:		count;
		block_type:			count;
		block_number:		count;
		start_addr_awl:		count;
		step_addr_counter:	count;
		items:				vector of S7UDReqDiagItem;
	};

	type S7UDReqDiagItemVec: vector of S7UDReqDiagItem;

	# VarTab1 Request

	type S7UDVarTab1ReqItem: record {
		mem_area:	count;
		rep_factor: count;
		db_number: 	count;
		start_addr: count;
	};

	type S7UDVarTab1ReqData: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		data_type:			count;
		byte_count:			count;
		item_count:			count;
		items:				vector of S7UDVarTab1ReqItem;
	};

	type S7UDVarTab1ReqItemVec: vector of S7UDVarTab1ReqItem;

	# VarTab1 Response

	type S7UDVarTab1ResItem: record {
		ret_value:		count;
		transport_size: count;
		length: 		count;
		data: 			count;
	};

	type S7UDVarTab1ResData: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		data_type:			count;
		byte_count:			count;
		item_count:			count;
		items:				vector of S7UDVarTab1ResItem;
	};

	type S7UDVarTab1ResItemVec: vector of S7UDVarTab1ResItem;

	## Function Group 2 Cyclic Data
	# Cyclic Mem, 5 different types for 5 different addressing methods...
	# Don't know if THIS is necessary, needs to be evaluated in the future
	type S7UDCyclMemAny: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		item_count:			count;
		interval_timebase:	count;
		interval_time:		count;
		items:				vector of S7AnyTypeItem;
	};

	type S7UDCyclMemDB: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		item_count:			count;
		interval_timebase:	count;
		interval_time:		count;
		items:				vector of S7DBTypeItem;
	};

	type S7UDCyclMemSym: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		item_count:			count;
		interval_timebase:	count;
		interval_time:		count;
		items:				vector of S71200SymTypeItem;
	};

	type S7UDCyclMemNCK: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		item_count:			count;
		interval_timebase:	count;
		interval_time:		count;
		items:				vector of S7NCKTypeItem;
	};

	type S7UDCyclMemDrive: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		item_count:			count;
		interval_timebase:	count;
		interval_time:		count;
		items:				vector of S7DriveAnyTypeItem;
	};

	type S7UDCyclMemDataAck: record { # For "push" or "reponse" types
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		item_count:			count;
		items:				vector of S7ReadWriteData;
	}; 

	type S7UDCycleMemDataAckVec: vector of S7ReadWriteData; # Vector of S7ReadWriteData Items

	## Function Group 3 Block Functions
	type S7UDBlockListItem: record {
		block_type:			count;
		block_count:		count;
	};

	type S7UDBlockListTypeItem: record {
		block_number:		count;
		block_flags:		count;
		block_language:		count;
	};

	type S7UDBlockList: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		items:				vector of S7UDBlockListItem;
	};

	type S7UDBlockListType: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		items:				vector of S7UDBlockListTypeItem;
	};
	
	type S7UDBlockInfoReq: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		block_type:			string;
		block_number:		string;
		filesystem:			string;
	};

	type S7UDBlockInfoRes: record {
		return_code:			count;
		transport_size:			count;
		data_length:			count;
		block_type:				count;
		info_length:			count;
		block_flags:			count;
		block_language:			count;
		subblk_type:			count;
		block_number:			count;
		length_load_memory:		count;
		block_security:			count;
		code_timestamp:			string;
		interface_timestamp:	string;
		ssb_length:				count;
		add_length:				count;
		localdata_length:		count;
		mc7_code_length:		count;
		author:					string;
		family:					string;
		name:					string;
		version:				count;
		block_checksum:			count;
		reserved1:				count;
		reserved2:				count;
	};

	type S7UDBlockListVec: vector of S7UDBlockListItem;
	type S7UDBlockListTypeVec: vector of S7UDBlockListTypeItem;

	## Function Group 4 - CPU

	## Function Group 6 - PBC

	type S7UDPBC: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		var_spec:			count;
		addr_length:		count;
		syntax_id:			count;
		pbc_unknown:		count;
		pbc_r_id:			count;
		data:				string;
	};

	## Function Group 7 - Time
	type S7UDTime: record {
		return_code:		count;
		transport_size:		count;
		data_length:		count;
		timestring:			string;
	};
}

module S7CommPlus;

export {

	type S7PHeader: record {
		protocol_id:	count;
		version:		count;
		data_length:	count;
	};

	type S7PTrailer: record {
		protocol_id:	count;
		version:		count;
		data_length:	count;
	};

	type S7PItemValueInfo: record {
		array_type:		count;
		array_size:		count;
		current_index:	count;
		context:		string;
		data_type:		count;
	};
}

module GLOBAL;
