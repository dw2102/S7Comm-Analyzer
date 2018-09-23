/**
 * S7CommPlus protocol analyzer.
 * 
 * Based on:
 * 
 * The Wireshark dissector written by Thomas Wiens
 * https://sourceforge.net/projects/s7commwireshark/
 * https://github.com/JuergenKosel/s7commwireshark
 *  
 * Author: Dane Wullen
 * Date: 10.05.2018
 * Version: 1.0
 * 
 * This plugin is a part of a master's thesis written at Fachhochschule in Aachen (Aachen University of Applied Sciences)
 * 
 */

#ifndef ANALYZER_PROTOCOL_S7COMM_PLUS_CONSTANTS_H
#define ANALYZER_PROTOCOL_S7COMM_PLUS_CONSTANTS_H

#define PROTO_TAG_S7COMM_PLUS           "S7COMM-PLUS"

/* Min. telegram length for heuristic check */
#define S7COMMP_MIN_TELEGRAM_LENGTH     4

/* Protocol identifier */
#define S7COMM_PLUS_PROT_ID             0x72

/* Protocol versions */
#define S7COMMP_PROTOCOLVERSION_1               0x01
#define S7COMMP_PROTOCOLVERSION_2               0x02
#define S7COMMP_PROTOCOLVERSION_3               0x03

/* Max number of array values displays on Item-Value tree. */
#define S7COMMP_ITEMVAL_ARR_MAX_DISPLAY 10

/**************************************************************************
 * PDU types
 */
#define S7COMMP_PDUTYPE_CONNECT                 0x01
#define S7COMMP_PDUTYPE_DATA                    0x02
#define S7COMMP_PDUTYPE_DATAFW1_5               0x03
#define S7COMMP_PDUTYPE_KEEPALIVE 0xff

/**************************************************************************
 * Opcodes in data part
 */
#define S7COMMP_OPCODE_REQ                      0x31
#define S7COMMP_OPCODE_RES                      0x32
#define S7COMMP_OPCODE_NOTIFICATION             0x33
#define S7COMMP_OPCODE_RES2                     0x02

/**************************************************************************
 * Function codes in data part.
 */
#define S7COMMP_FUNCTIONCODE_EXPLORE            0x04bb
#define S7COMMP_FUNCTIONCODE_CREATEOBJECT       0x04ca
#define S7COMMP_FUNCTIONCODE_DELETEOBJECT       0x04d4
#define S7COMMP_FUNCTIONCODE_SETVARIABLE        0x04f2
#define S7COMMP_FUNCTIONCODE_GETLINK            0x0524
#define S7COMMP_FUNCTIONCODE_SETMULTIVAR        0x0542
#define S7COMMP_FUNCTIONCODE_GETMULTIVAR        0x054c
#define S7COMMP_FUNCTIONCODE_BEGINSEQUENCE      0x0556
#define S7COMMP_FUNCTIONCODE_ENDSEQUENCE        0x0560
#define S7COMMP_FUNCTIONCODE_INVOKE             0x056b
#define S7COMMP_FUNCTIONCODE_GETVARSUBSTR       0x0586

/**************************************************************************
 * Data types
 */
#define S7COMMP_ITEM_DATATYPE_NULL              0x00
#define S7COMMP_ITEM_DATATYPE_BOOL              0x01        /* BOOL: fix 1 Byte */
#define S7COMMP_ITEM_DATATYPE_USINT             0x02        /* USINT, CHAR: fix 1 Byte */
#define S7COMMP_ITEM_DATATYPE_UINT              0x03        /* UINT, DATE: fix 2 Bytes */
#define S7COMMP_ITEM_DATATYPE_UDINT             0x04        /* UDint: varuint32 */
#define S7COMMP_ITEM_DATATYPE_ULINT             0x05        /* ULInt: varuint64 */
#define S7COMMP_ITEM_DATATYPE_SINT              0x06        /* SINT: fix 1 Bytes */
#define S7COMMP_ITEM_DATATYPE_INT               0x07        /* INT: fix 2 Bytes */
#define S7COMMP_ITEM_DATATYPE_DINT              0x08        /* DINT, TIME: varint32 */
#define S7COMMP_ITEM_DATATYPE_LINT              0x09        /* LInt: varint64 */
#define S7COMMP_ITEM_DATATYPE_BYTE              0x0a        /* BYTE: fix 1 Byte */
#define S7COMMP_ITEM_DATATYPE_WORD              0x0b        /* WORD: fix 2 Bytes */
#define S7COMMP_ITEM_DATATYPE_DWORD             0x0c        /* DWORD: fix 4 Bytes */
#define S7COMMP_ITEM_DATATYPE_LWORD             0x0d        /* LWORD: fix 8 Bytes */
#define S7COMMP_ITEM_DATATYPE_REAL              0x0e        /* REAL: fix 4 Bytes */
#define S7COMMP_ITEM_DATATYPE_LREAL             0x0f        /* LREAL: fix 8 Bytes */
#define S7COMMP_ITEM_DATATYPE_TIMESTAMP         0x10        /* TIMESTAMP: e.g reading CPU from TIA portal, fix 8 Bytes */
#define S7COMMP_ITEM_DATATYPE_TIMESPAN          0x11        /* TIMESPAN: e.g. reading cycle time from TIA portal, varuint64 */
#define S7COMMP_ITEM_DATATYPE_RID               0x12        /* RID: fix 4 Bytes */
#define S7COMMP_ITEM_DATATYPE_AID               0x13        /* AID: varuint32*/
#define S7COMMP_ITEM_DATATYPE_BLOB              0x14
#define S7COMMP_ITEM_DATATYPE_WSTRING           0x15        /* Wide string with length header, UTF8 encoded */
#define S7COMMP_ITEM_DATATYPE_VARIANT           0x16
#define S7COMMP_ITEM_DATATYPE_STRUCT            0x17
                                                            /* 0x18 ?? */
#define S7COMMP_ITEM_DATATYPE_S7STRING          0x19        /* S7 String with maximum length of 254 characters, only for tag-description */

/* Datatype flags */
#define S7COMMP_DATATYPE_FLAG_ARRAY             0x10
#define S7COMMP_DATATYPE_FLAG_ADDRESS_ARRAY     0x20
#define S7COMMP_DATATYPE_FLAG_SPARSEARRAY       0x40

/**************************************************************************
 * Element-IDs
 */
#define S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT   0xa1
#define S7COMMP_ITEMVAL_ELEMENTID_TERMOBJECT    0xa2
#define S7COMMP_ITEMVAL_ELEMENTID_ATTRIBUTE     0xa3
#define S7COMMP_ITEMVAL_ELEMENTID_RELATION      0xa4
#define S7COMMP_ITEMVAL_ELEMENTID_STARTTAGDESC  0xa7
#define S7COMMP_ITEMVAL_ELEMENTID_TERMTAGDESC   0xa8
#define S7COMMP_ITEMVAL_ELEMENTID_VARTYPELIST   0xab
#define S7COMMP_ITEMVAL_ELEMENTID_VARNAMELIST   0xac

/* Item access area */
#define S7COMMP_VAR_ITEM_AREA1_DB               0x8a0e              /* Reading DB, 2 byte DB-Number following */
#define S7COMMP_VAR_ITEM_AREA1_IQMCT            0x0000              /* Reading I/Q/M/C/T, 2 Byte detail area following */
#define S7COMMP_VAR_ITEM_AREA2_DB               0x8a0e
#define S7COMMP_VAR_ITEM_AREA2_I                0x50
#define S7COMMP_VAR_ITEM_AREA2_Q                0x51
#define S7COMMP_VAR_ITEM_AREA2_M                0x52
#define S7COMMP_VAR_ITEM_AREA2_C                0x53
#define S7COMMP_VAR_ITEM_AREA2_T                0x54

/* Explore areas */
#define S7COMMP_EXPLORE_CLASS_IQMCT             0x90
#define S7COMMP_EXPLORE_CLASS_UDT               0x91
#define S7COMMP_EXPLORE_CLASS_DB                0x92
#define S7COMMP_EXPLORE_CLASS_FB                0x93
#define S7COMMP_EXPLORE_CLASS_FC                0x94
#define S7COMMP_EXPLORE_CLASS_OB                0x95
#define S7COMMP_EXPLORE_CLASS_FBT               0x96
#define S7COMMP_EXPLORE_CLASS_LIB               0x02
#define S7COMMP_EXPLORE_CLASS_IQMCT_INPUT       0x01
#define S7COMMP_EXPLORE_CLASS_IQMCT_OUTPUT      0x02
#define S7COMMP_EXPLORE_CLASS_IQMCT_BITMEM      0x03
#define S7COMMP_EXPLORE_CLASS_IQMCT_04          0x04
#define S7COMMP_EXPLORE_CLASS_IQMCT_TIMER       0x05
#define S7COMMP_EXPLORE_CLASS_IQMCT_COUNTER     0x06
#define S7COMMP_EXPLORE_CLASS_LIB_STYPE         0x00
#define S7COMMP_EXPLORE_CLASS_LIB_STYPEARR      0x01
#define S7COMMP_EXPLORE_CLASS_LIB_SFC           0x02
#define S7COMMP_EXPLORE_CLASS_LIB_SFB           0x03
#define S7COMMP_EXPLORE_CLASS_LIB_FBT           0x04
#define S7COMMP_EXPLORE_CLASS_LIB_FB            0x05
#define S7COMMP_EXPLORE_CLASS_LIB_FC            0x06
#define S7COMMP_EXPLORE_CLASS_LIB_FCT           0x07
#define S7COMMP_EXPLORE_CLASS_LIB_UDT           0x08
#define S7COMMP_EXPLORE_CLASS_LIB_STRUCT        0x09

/* Attribute flags in tag description */
#define S7COMMP_TAGDESCR_ATTRIBUTE_HOSTRELEVANT         0x8000000
#define S7COMMP_TAGDESCR_ATTRIBUTE_PLAINMEMBERRETAIN    0x2000000
#define S7COMMP_TAGDESCR_ATTRIBUTE_PLAINMEMBERCLASSIC   0x1000000
#define S7COMMP_TAGDESCR_ATTRIBUTE_HMIVISIBLE           0x0800000
#define S7COMMP_TAGDESCR_ATTRIBUTE_HMIREADONLY          0x0400000
#define S7COMMP_TAGDESCR_ATTRIBUTE_HMICACHED            0x0200000
#define S7COMMP_TAGDESCR_ATTRIBUTE_HMIACCESSIBLE        0x0100000
#define S7COMMP_TAGDESCR_ATTRIBUTE_ISQUALIFIER          0x0040000
#define S7COMMP_TAGDESCR_ATTRIBUTE_NORMALACCESS         0x0008000
#define S7COMMP_TAGDESCR_ATTRIBUTE_NEEDSLEGITIMIZATION  0x0004000
#define S7COMMP_TAGDESCR_ATTRIBUTE_CHANGEBLEINRUN       0x0002000
#define S7COMMP_TAGDESCR_ATTRIBUTE_SERVERONLY           0x0000800
#define S7COMMP_TAGDESCR_ATTRIBUTE_CLIENTREADRONLY      0x0000400
#define S7COMMP_TAGDESCR_ATTRIBUTE_SEPLOADMEMFA         0x0000200
#define S7COMMP_TAGDESCR_ATTRIBUTE_ASEVALREQ            0x0000100
#define S7COMMP_TAGDESCR_ATTRIBUTE_BL                   0x0000040
#define S7COMMP_TAGDESCR_ATTRIBUTE_PERSISTENT           0x0000020
#define S7COMMP_TAGDESCR_ATTRIBUTE_CORE                 0x0000010
#define S7COMMP_TAGDESCR_ATTRIBUTE_ISOUT                0x0000008
#define S7COMMP_TAGDESCR_ATTRIBUTE_ISIN                 0x0000004
#define S7COMMP_TAGDESCR_ATTRIBUTE_APPWRITEABLE         0x0000002
#define S7COMMP_TAGDESCR_ATTRIBUTE_APPREADABLE          0x0000001

/* Offsetinfo type for tag description */
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_LIBELEMENT      0x00
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_BOOLINUDT       0x01
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_ARRAYINSTRUCT   0x02
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_PLAINSTATIC     0x04
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_BOOL            0x05
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_ARRAY           0x06
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_MULTIDIMARRAY   0x07

#define S7COMMP_ARRAY                                   0x10
#define S7COMMP_ADDRESS_ARRAY                           0x20
#define S7COMMP_SPARSE_ARRAY                            0x40
#define S7COMMP_UNKNOWN_ARRAY                           0x80

#endif