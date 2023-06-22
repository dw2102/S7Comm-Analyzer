module S7_Const;

export {
    const subfunction_names_group_1: table[count] of string = {
        [0x01] = "Request Diag Data 1",
        [0x02] = "VarTab 1",
        [0x0c] = "Erase",
        [0x0e] = "Read Diag Data",
        [0x0f] = "Remove Diag Data",
        [0x10] = "Force",
        [0x13] = "Request Diag Data 2",
    } &default=function(idx: count): string { return fmt("Unknown Type: %d", idx);};

    const subfunction_names_group_2: table[count] of string = {
        [0x01] = "Memory",
        [0x04] = "Unsubscribe",
        [0x05] = "Memory 2",
    } &default=function(idx: count): string { return fmt("Unknown Type: %d", idx);};

    const subfunction_names_group_3: table[count] of string = {
        [0x01] = "List Blocks",
        [0x02] = "List Blocks of Type",
        [0x03] = "Get Block Info",
    } &default=function(idx: count): string { return fmt("Unknown Type: %d", idx);};

    const subfunction_names_group_4: table[count] of string = {
        [0x01] = "Read SZL",
        [0x02] = "Message",
        [0x03] = "Diag Message",
        [0x05] = "Alarm 8 IND",
        [0x06] = "Notify IND",
        [0x07] = "Alarm 8 Lock",
        [0x08] = "Alarm 8 Unlock",
        [0x09] = "Scan IND",
        [0x0b] = "Alarm Ack",
        [0x0c] = "Alarm Ack IND",
        [0x0d] = "Alarm 8 Lock IND",
        [0x0e] = "Alarm 8 Unlock IND",
        [0x11] = "Alarm SQ Ind",
        [0x12] = "Alarm S Ind",
        [0x13] = "Alarm Query",
        [0x16] = "Notify 8 IND",
    } &default=function(idx: count): string { return fmt("Unknown Type: %d", idx);};

    const subfunction_names_group_5: table[count] of string = {
        [0x01] = "Security Password",
    } &default=function(idx: count): string { return fmt("Unknown Type: %d", idx);};

    const subfunction_names_group_7: table[count] of string = {
        [0x01] = "Time Read",
        [0x02] = "Time Set",
        [0x03] = "Time Read_F",
        [0x04] = "Time Set 2",
    } &default=function(idx: count): string { return fmt("Unknown Type: %d", idx);};

    const subfunction_names_group_15: table[count] of string = {
        [0x01] = "Request Download",
        [0x02] = "Download Block",
        [0x03] = "Continue Download",
        [0x04] = "Download Ended",
        [0x06] = "Start Upload",
        [0x07] = "Upload",
        [0x08] = "Continue Upload",
    } &default=function(idx: count): string { return fmt("Unknown Type: %d", idx);};
}