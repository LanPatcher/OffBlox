-- main.server.lua
-- This runs automatically when Roblox Studio loads

local RunService = game:GetService("RunService")
local toolbar = plugin:CreateToolbar("My Plugin")
local button = toolbar:CreateButton("Run", "Click to do something", "")

-- Fires when the Play button is pressed in Studio
RunService.Run:Connect(function()
    print("Playtest started!")
    -- Put your runtime logic here
end)

-- Fires when Stop is pressed
game:GetService("RunService").Stopped:Connect(function()
    print("Playtest stopped!")
end)

-- Optional: toolbar button click
button.Click:Connect(function()
    print("Button clicked!")
end)

print("MyPlugin loaded into Studio!")