local ip_IHL = Field.new("ip.hdr_len")
local tcp_data_offset = Field.new("tcp.hdr_len")
--local sm_length = Field.new("smpp.sm_length")
local window = nil

local commands = {
                  [4]          = 'SUBMIT_SM', 
                  [5]          = 'DELIVER_SM',
                  [2147483652] = 'SUBMIT_SM_RESP',
                  [2147483653] = 'DELIVER_SM_RESP'
}

local operations = {
                  ['SUBMIT_SM'] = 4, 
                  ['DELIVER_SM'] = 5,
                  ['SUBMIT_SM_RESP'] = 2147483652,
                  ['DELIVER_SM_RESP'] = 2147483653 
}

local function make_text_window()
    window = TextWindow.new("Look through tcp data")
    window:set_atclose(function () tap:remove() end)
end

local function create_listener()
    tap = Listener.new(nil, "smpp")
end

local function read_c_octet_string(buffer)
    zero_byte = nil
end

local function c_string_len(buffer,start_point)
    window:append("[c octet measure]")
    local offset = 0
    local is_zero = false
    curr_byte = nil
    while(not is_zero)
        do
        curr_byte =  buffer(offset+start_point,1):uint()
        window:append(string.format("curr_byte = %s\n", tostring(curr_byte)))
        if(curr_byte ~= 0) then 
            offset = offset + 1
        else
            offset = offset + 1
            is_zero = true
        end
    window:append(string.format("cycle number = %d\n", offset))
    end
    return offset
end


local function smpp_table (byte_buffer, packet_info)
    local fields={                               -- universal fields minimum for work
            packet_number = packet_info.number,                               
            packet_len = nil,
            command_id = nil,
            command_status = nil,
            sequence_number = nil,
            message_len = nil,             -- for SUBMIT_SM and DELIVER_SM in other packets = nil
            message_id = nil     -- for DELIVER_SM and SUBMIT_SM_RESP only in other packets = nil
    }
    
    fields.packet_len = byte_buffer(0, 4):uint()
    fields.command_id = byte_buffer(4, 4):uint()
    fields.command_status = byte_buffer(8, 4):uint()
    fields.sequence_number = byte_buffer(12, 4):uint()
    window:append("smpp table called\n")
    window:append(string.format("Command id = %d\nsequence_number = %d\n", fields.command_id, fields.sequence_number)) -- DEBUG
    if (command_id == operations['DELIVER_SM'] or command_id == operations['SUBMIT_SM'])
        then
        service_type_len = c_string_len(byte_buffer, 16)
        fields.message_len = byte_buffer(0, 1)
    end -- TODO byte_buffer offset
    
    if (command_id == operations['DELIVER_SM']) then
        tag_offset = fields.message_len + message_offset 
        fields.message_id = byte_buffer() -- TODO
    elseif (command_id == operations['SUBMIT_SM_RESP']) then
        fields.message_id = byte_buffer() --TODO
    end

    return fields
end


local function split_tcp_data(segment_buffer, packet_info)
    local smpp_packets = {}
    local buffer_len = segment_buffer:len()
    local eth_header_len = 14   --ethernet header length
    local ip_header = ip_IHL().value  -- get ip data offset  
    local tcp_header = tcp_data_offset().value
    local total_offset = eth_header_len + ip_header + tcp_header    -- get tcp data offset
    local smpp_raw_data = segment_buffer(total_offset, buffer_len - total_offset) -- get raw data bytes
    window:append(string.format("smpp data = %s\n",tostring(smpp_raw_data))) --DEBUG    
	local is_last = false
    local start_smpp_offset = 0
    window:append("split called \n")
    window:append("[pack started] \n")
    while (not is_last) -- for each smpp packet 
        do
        window:append("inside while\n")
        if (start_smpp_offset >= smpp_raw_data:len()) then
            is_last = true
        window:append("last byte of pack here\n")
        else
            smpp_packet_len = smpp_raw_data(start_smpp_offset, 4):uint()
            window:append(string.format("smpp segment len = %s\n", smpp_packet_len))
            smpp_packet_bytes = smpp_raw_data(start_smpp_offset, smpp_packet_len)   -- get single raw smpp packet 
            table.insert(smpp_packets, smpp_table(smpp_packet_bytes, packet_info))  -- add smpp packet info to table 
            start_smpp_offset = start_smpp_offset + smpp_packet_len
        end
    end
    window:append("outside while\n")
    window:append("[pack finished] \n\n\n")
    return smpp_packets -- table with several smpp packet credentials
end

local function filter_packets()
    create_listener()
    make_text_window()
    create_listener()
	function tap.packet(pinfo, tvb)
        split_tcp_data(tvb, pinfo)
    end
    retap_packets()
end

register_menu("_search in smpp data", filter_packets, MENU_TOOLS_UNSORTED)
