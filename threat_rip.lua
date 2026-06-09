-- Api Base
local API_BASE_URL = "https://www.threat.rip/api/upload/file"
local API_BASE_URL_REPORT_URL = "https://www.threat.rip/api/reports/file"
local COMMON_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
local http = require('coro-http')
local json = require('json')
local fs = require('fs')

local ThreatRip = {}

local function construct_headers(apiKey, options)
    local headers = {
        {"Authorization", apiKey},
        {"User-Agent", COMMON_USER_AGENT},
        {"Accept", "application/json"}
    }
    if options then
        if options.cookie then table.insert(headers, {"Cookie", options.cookie}) end
        if options.userToken then 
            table.insert(headers, {"x-user-token", options.userToken})
            table.insert(headers, {"Cookie", "usertoken=" .. options.userToken .. "; token=" .. options.userToken})
        end
    end
    return headers
end

-- Handles raw byte uploads or local files
function ThreatRip.upload(data, filename, apiKey, options, callback)
    if type(options) == "function" then callback = options; options = nil end
    
    coroutine.wrap(function()
        local content = data
        if not filename then filename = "file.bin" end

        -- Improved heuristic: check if data is a valid existing file path
        if type(data) == "string" and #data < 4096 then
            local stat = fs.statSync(data)
            if stat and stat.type == "file" then
                content = fs.readFileSync(data)
            end
        end

        local boundary = "----LuvitBoundary" .. tostring(os.time())
        local payload = "--" .. boundary .. "\r\n" ..
                        "Content-Disposition: form-data; name=\"file\"; filename=\"" .. filename .. "\"\r\n" ..
                        "Content-Type: application/octet-stream\r\n\r\n" ..
                        content .. "\r\n" ..
                        "--" .. boundary .. "\r\n" ..
                        "Content-Disposition: form-data; name=\"password\"\r\n\r\n" .. (options and options.password or "") .. "\r\n" ..
                        "--" .. boundary .. "--\r\n"

        local headers = construct_headers(apiKey, options)
        table.insert(headers, {"Content-Type", "multipart/form-data; boundary=" .. boundary})

        local response, body = http.request("POST", API_BASE_URL, headers, payload)

        if not response then
            if callback then callback("Network request failed (no response)") end
            return
        end

        if response.code ~= 200 then
            if callback then callback("API request failed: " .. response.code) end
            return
        end

        local success, res_data = pcall(json.decode, body)
        if callback then callback(not success and "JSON Error" or nil, res_data or body) end
    end)()
end

local function internal_get(url, apiKey, options, callback)
    if type(options) == "function" then callback = options; options = nil end
    coroutine.wrap(function()
        local headers = construct_headers(apiKey, options)
        local res, body = http.request("GET", url, headers)
        if not res then
            if callback then callback("Network request failed (no response)") end
            return
        end

        local success, data = pcall(json.decode, body)
        -- 200 (OK) and 404 (NOT FOUND) both return valid JSON objects per API docs.
        -- We pass the status code as the third argument to allow callers to handle existence logic.
        if res.code == 200 or res.code == 404 then
            if callback then callback(not success and body ~= "" and "JSON Error" or nil, data or body, res.code) end
        else
            if callback then callback("Request failed: " .. res.code, body, res.code) end
        end
    end)()
end

function ThreatRip.file_report(hash, apiKey, options, callback)
    internal_get(string.format("%s/%s", API_BASE_URL_REPORT_URL, hash), apiKey, options, callback)
end

function ThreatRip.get_classification(hash, apiKey, options, callback)
    internal_get(string.format("%s/%s/classification", API_BASE_URL_REPORT_URL, hash), apiKey, options, callback)
end

function ThreatRip.check_file_exists(hash, apiKey, options, callback)
    internal_get(string.format("%s/%s/exists", API_BASE_URL_REPORT_URL, hash), apiKey, options, function(err, data, code)
        if callback then
            if err then return callback(err) end
            -- Existence is determined by the status code: 200 Found, 404 Not Found.
            -- We return a boolean 'exists' as the second result.
            local exists = (code == 200)
            callback(nil, exists, data)
        end
    end)
end

function ThreatRip.get_metadata(hash, apiKey, options, callback)
    internal_get(string.format("%s/%s/metadata", API_BASE_URL_REPORT_URL, hash), apiKey, options, callback)
end

function ThreatRip.get_config(hash, apiKey, options, callback)
    internal_get(string.format("%s/%s/config", API_BASE_URL_REPORT_URL, hash), apiKey, options, callback)
end

function ThreatRip.fetch_remote(remoteUrl, apiKey, options, callback)
    if type(options) == "function" then callback = options; options = nil end
    coroutine.wrap(function()
        local boundary = "----LuvitBoundary" .. tostring(os.time())
        local payload = "--" .. boundary .. "\r\n" ..
                        "Content-Disposition: form-data; name=\"remote\"\r\n\r\n" ..
                        remoteUrl .. "\r\n" ..
                        "--" .. boundary .. "\r\n" ..
                        "Content-Disposition: form-data; name=\"password\"\r\n\r\n" ..
                        (options and options.password or "") .. "\r\n" ..
                        "--" .. boundary .. "--\r\n"

        local headers = construct_headers(apiKey, options)
        table.insert(headers, {"Content-Type", "multipart/form-data; boundary=" .. boundary})

        local response, body = http.request("POST", "https://www.threat.rip/api/upload/fetch", headers, payload)

        if not response then
            if callback then callback("Network request failed (no response)") end
            return
        end

        if response.code ~= 200 then
            if callback then callback("API request failed: " .. response.code) end
            return
        end

        local success, res_data = pcall(json.decode, body)
        if callback then callback(not success and "JSON Error" or nil, res_data or body) end
    end)()
end

return ThreatRip
