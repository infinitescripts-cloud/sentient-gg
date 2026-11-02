-- Example only: place this in a server-only Roblox Script.
-- Enable HttpService in Game Settings and keep the license key out of client code.
-- Replace these values with your deployed Worker URL and a key created in Sentinel.

local HttpService = game:GetService("HttpService")
local WorkerBaseUrl = "https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev"
local ScriptId = "your-script-id"
local LicenseKey = "SENTINEL-REPLACE-ME" -- Keep this in server-only configuration.

local function validateLicense(player)
    local response
    local ok, err = pcall(function()
        response = HttpService:RequestAsync({
            Url = WorkerBaseUrl .. "/api/license/validate",
            Method = "POST",
            Headers = { ["Content-Type"] = "application/json" },
            Body = HttpService:JSONEncode({
                key = LicenseKey,
                scriptId = ScriptId,
                -- Account-scoped identifier for this example; tell users how it is used.
                hwid = tostring(player.UserId),
            }),
        })
    end)

    if not ok or not response or not response.Success then
        warn("Sentinel validation request failed:", err or (response and response.StatusCode))
        return false
    end

    local decodedOk, data = pcall(function()
        return HttpService:JSONDecode(response.Body)
    end)
    return decodedOk and data.valid == true
end

-- Call validateLicense(player) from your own server-side access-control flow.
-- Do not use a client LocalScript as the authority for valuable game logic.
return validateLicense