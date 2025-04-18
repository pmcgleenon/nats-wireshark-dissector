--[[
NATS Protocol Dissector for Wireshark

This dissector implements the NATS client protocol (port 4222) for Wireshark.
It decodes and displays NATS protocol messages in a human-readable format.

Supported Protocol Features:
- Basic commands (PUB, SUB, UNSUB, MSG)
- Headers (HPUB, HMSG)
- Queue groups
- Auto-unsubscribe
- JSON payloads
- Protocol acknowledgments (+OK/-ERR)
- Error handling

Protocol Message Types:
- INFO: Server information and configuration
- CONNECT: Client connection details
- PUB/HPUB: Publish messages (with/without headers)
- SUB: Subscribe to subjects
- UNSUB: Unsubscribe from subjects
- MSG/HMSG: Message delivery (with/without headers)
- PING/PONG: Keep-alive messages
- +OK/-ERR: Protocol acknowledgments

The dissector displays:
- Command type and parameters
- Subject names
- Subscription IDs
- Queue groups
- Headers (for HPUB/HMSG)
- Message payloads (with JSON parsing)
- Error messages

Note: This dissector is for the NATS client protocol only.
The NATS cluster protocol (port 6222) uses a different binary protocol.
]]

local json = require("dkjson")

local nats_proto = Proto("nats", "NATS Protocol")

-- Declare protocol fields
local f_command = ProtoField.string("nats.command", "Command")
local f_subject = ProtoField.string("nats.subject", "Subject")
local f_sid = ProtoField.string("nats.sid", "Subscription ID")
local f_reply_to = ProtoField.string("nats.reply_to", "Reply Subject")
local f_payload = ProtoField.string("nats.payload", "Payload")
local f_headers = ProtoField.string("nats.headers", "Headers")
local f_error = ProtoField.string("nats.error", "Error Message")
local f_status = ProtoField.string("nats.status", "Status")
local f_queue_group = ProtoField.string("nats.queue_group", "Queue Group")
local f_header_bytes = ProtoField.uint32("nats.header_bytes", "Header Bytes")
local f_total_bytes = ProtoField.uint32("nats.total_bytes", "Total Bytes")
local f_max_msgs = ProtoField.uint32("nats.max_msgs", "Max Messages")

nats_proto.fields = { 
    f_command, f_subject, f_sid, f_reply_to, f_payload, f_headers, 
    f_error, f_status, f_queue_group, f_header_bytes, f_total_bytes, f_max_msgs 
}

local function add_json_tree(json_obj, tree)
    if not tree then return end
    if type(json_obj) == "table" then
        for k, v in pairs(json_obj) do
            if type(v) == "table" then
                local subtree = tree:add(k)
                add_json_tree(v, subtree)
            else
                tree:add(k .. ": " .. tostring(v))
            end
        end
    else
        tree:set_text(tostring(json_obj))
    end
end

local function parse_headers(headers_str)
    if not headers_str then return {} end
    local headers = {}
    local lines = {}
    for line in headers_str:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end
    
    -- Skip the NATS/1.0 version line
    for i = 2, #lines do
        local line = lines[i]
        local name, value = line:match("([^:]+):%s*(.+)")
        if name and value then
            if not headers[name] then
                headers[name] = {}
            end
            table.insert(headers[name], value)
        end
    end
    return headers
end

local function safe_add_field(tree, field, value)
    if not tree or not field then return end
    if value then
        tree:add(field, value)
    end
end

function nats_proto.dissector(buffer, pinfo, tree)
    if not buffer or not pinfo or not tree then return end
    
    pinfo.cols.protocol = "NATS"

    local subtree = tree:add(nats_proto, buffer())
    local packet_str = buffer():string()

    -- Split into commands (each command ends with \r\n)
    local commands = {}
    local pos = 1
    while pos <= #packet_str do
        local cmd_end = packet_str:find("\r\n", pos)
        if not cmd_end then break end
        
        local cmd_line = packet_str:sub(pos, cmd_end - 1)
        if cmd_line ~= "" then  -- Only add non-empty lines
            -- Check if this line is a command or a payload
            local first_char = cmd_line:sub(1,1)
            if first_char ~= "{" and first_char ~= "[" then  -- Not a JSON payload
                table.insert(commands, {line = cmd_line, start = pos, end_pos = cmd_end})
            end
        end
        pos = cmd_end + 2
    end

    -- Build info string for the packet list
    local info_parts = {}
    for i, cmd_info in ipairs(commands) do
        local cmd_line = cmd_info.line
        local tokens = {}
        for token in cmd_line:gmatch("[^%s]+") do
            table.insert(tokens, token)
        end

        local cmd = tokens[1]
        if cmd then
            if cmd == "MSG" or cmd == "HMSG" then
                table.insert(info_parts, string.format("%s %s", cmd, tokens[2] or ""))
            elseif cmd == "PUB" or cmd == "HPUB" then
                table.insert(info_parts, string.format("%s %s", cmd, tokens[2] or ""))
            elseif cmd == "SUB" then
                table.insert(info_parts, string.format("%s %s", cmd, tokens[2] or ""))
            elseif cmd == "INFO" then
                table.insert(info_parts, "INFO")
            elseif cmd == "CONNECT" then
                table.insert(info_parts, "CONNECT")
            elseif cmd == "PING" then
                table.insert(info_parts, "PING")
            elseif cmd == "PONG" then
                table.insert(info_parts, "PONG")
            elseif cmd == "-ERR" then
                table.insert(info_parts, "ERROR")
            elseif cmd == "NATS/1.0" then
                table.insert(info_parts, string.format("NATS/1.0 %s", tokens[2] or ""))
            else
                table.insert(info_parts, cmd)
            end
        end
    end

    -- Set the info column with space separator
    pinfo.cols.info = table.concat(info_parts, " ")

    -- Process each command for the tree view
    for i, cmd_info in ipairs(commands) do
        local cmd_line = cmd_info.line
        local tokens = {}
        for token in cmd_line:gmatch("[^%s]+") do
            table.insert(tokens, token)
        end

        local cmd = tokens[1]
        if not cmd then goto continue end

        local cmd_tree = subtree:add(f_command, cmd)
        if not cmd_tree then goto continue end

        if cmd == "INFO" or cmd == "CONNECT" then
            local json_str = cmd_line:sub(#cmd + 2)
            local obj, pos, err = json.decode(json_str, 1, nil)

            if err then
                safe_add_field(cmd_tree, f_payload, "Invalid JSON: " .. err)
            else
                local json_tree = cmd_tree:add(f_payload, "JSON Payload")
                add_json_tree(obj, json_tree)
            end

        elseif cmd == "PUB" or cmd == "HPUB" then
            safe_add_field(cmd_tree, f_subject, tokens[2])

            local index = 3
            if #tokens == 4 or #tokens == 5 then
                safe_add_field(cmd_tree, f_reply_to, tokens[index])
                index = index + 1
            end

            if cmd == "HPUB" then
                local header_bytes = tonumber(tokens[index])
                local total_bytes = tonumber(tokens[index + 1])
                safe_add_field(cmd_tree, f_header_bytes, header_bytes)
                safe_add_field(cmd_tree, f_total_bytes, total_bytes)
                index = index + 2
            end

            local payload_size = tonumber(tokens[index])
            if payload_size then
                local payload_start = cmd_info.end_pos + 2
                if payload_start then
                    local payload_buf = buffer(payload_start - 1, payload_size)
                    local payload_str = payload_buf:string()
                    
                    if cmd == "HPUB" then
                        -- Parse headers
                        local header_end = payload_str:find("\r\n\r\n")
                        if header_end then
                            local headers_str = payload_str:sub(1, header_end - 1)
                            local headers = parse_headers(headers_str)
                            local headers_tree = cmd_tree:add(f_headers, "Headers")
                            if headers_tree then
                                for name, values in pairs(headers) do
                                    for _, value in ipairs(values) do
                                        headers_tree:add(name .. ": " .. value)
                                    end
                                end
                            end
                            payload_str = payload_str:sub(header_end + 4)
                        end
                    end
                    
                    -- Try to parse as JSON if it looks like JSON
                    if payload_str:match("^%s*{") then
                        local obj, pos, err = json.decode(payload_str, 1, nil)
                        if not err then
                            local json_tree = cmd_tree:add(f_payload, "JSON Payload")
                            add_json_tree(obj, json_tree)
                        else
                            safe_add_field(cmd_tree, f_payload, payload_str)
                        end
                    else
                        safe_add_field(cmd_tree, f_payload, payload_str)
                    end
                end
            end

        elseif cmd == "SUB" then
            safe_add_field(cmd_tree, f_subject, tokens[2])
            if #tokens == 4 then
                safe_add_field(cmd_tree, f_queue_group, tokens[3])
                safe_add_field(cmd_tree, f_sid, tokens[4])
            else
                safe_add_field(cmd_tree, f_sid, tokens[3])
            end

        elseif cmd == "UNSUB" then
            safe_add_field(cmd_tree, f_sid, tokens[2])
            if tokens[3] then
                safe_add_field(cmd_tree, f_max_msgs, tokens[3])
            end

        elseif cmd == "MSG" or cmd == "HMSG" then
            safe_add_field(cmd_tree, f_subject, tokens[2])
            safe_add_field(cmd_tree, f_sid, tokens[3])
            local idx = 4
            if #tokens == 5 or #tokens == 6 then
                safe_add_field(cmd_tree, f_reply_to, tokens[idx])
                idx = idx + 1
            end

            if cmd == "HMSG" then
                local header_bytes = tonumber(tokens[idx])
                local total_bytes = tonumber(tokens[idx + 1])
                safe_add_field(cmd_tree, f_header_bytes, header_bytes)
                safe_add_field(cmd_tree, f_total_bytes, total_bytes)
                idx = idx + 2
            end

            local payload_size = tonumber(tokens[idx])
            if payload_size then
                local payload_start = cmd_info.end_pos + 2
                if payload_start then
                    local payload_buf = buffer(payload_start - 1, payload_size)
                    local payload_str = payload_buf:string()
                    
                    if cmd == "HMSG" then
                        -- Parse headers
                        local header_end = payload_str:find("\r\n\r\n")
                        if header_end then
                            local headers_str = payload_str:sub(1, header_end - 1)
                            local headers = parse_headers(headers_str)
                            local headers_tree = cmd_tree:add(f_headers, "Headers")
                            if headers_tree then
                                for name, values in pairs(headers) do
                                    for _, value in ipairs(values) do
                                        headers_tree:add(name .. ": " .. value)
                                    end
                                end
                            end
                            payload_str = payload_str:sub(header_end + 4)
                        end
                    end
                    
                    -- Try to parse as JSON if it looks like JSON
                    if payload_str:match("^%s*{") then
                        local obj, pos, err = json.decode(payload_str, 1, nil)
                        if not err then
                            local json_tree = cmd_tree:add(f_payload, "JSON Payload")
                            add_json_tree(obj, json_tree)
                        else
                            safe_add_field(cmd_tree, f_payload, payload_str)
                        end
                    else
                        safe_add_field(cmd_tree, f_payload, payload_str)
                    end
                end
            end

        elseif cmd == "PING" or cmd == "PONG" or cmd == "+OK" then
            -- no extra fields required

        elseif cmd == "-ERR" then
            safe_add_field(cmd_tree, f_error, cmd_line:sub(6))

        elseif cmd == "NATS/1.0" then
            local status_tree = subtree:add(f_status, cmd_line)
            if status_tree and tokens[2] then
                status_tree:add("Code", tokens[2])
            end

        else
            safe_add_field(cmd_tree, f_payload, cmd_line:sub(#cmd + 2))
        end

        ::continue::
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(4222, nats_proto)

