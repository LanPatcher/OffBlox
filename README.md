Roblox LAN 2026 client (NOT A REVIVAL) this is a dev/play-test tool intended to be used so you can play offline with friends,
it is NOT built with intended profit and it was NOT built with the intent to replace roblox or be a massive community-run tool
it is explicitly for the intended use of running games offline (Not needing to use roblox's servers for any tasks), and playing with friends

Discord:

https://discord.gg/pbPCjpp26k


Playing on windows is easy the launcher will handle everything.



Semi-Support for hosting a Roblox Server on the latest WINE version via Linux (Tested on WSL may be buggy):

WARNING: DO NOT ATTEMPT TO PLAY THIS ON WINE/LINUX (Hosting works but not playing) AS RENDERING ON LINUX IS SUPER BROKEN SO FAR

Set server.rbxl before hosting!!!

PREFIX="${WINEPREFIX:-$HOME/.wine}"
USERDIR=$(ls -d "$PREFIX"/drive_c/users/*/ | grep -vi public | head -1)
DEST="${USERDIR}AppData/Local/Roblox"
mkdir -p "$DEST"
cat > "$DEST/server.rbxl" <<'EOF'
<roblox xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.roblox.com/roblox.xsd" version="4">
  <Item class="Workspace" referent="RBX0">
    <Properties>
      <bool name="FilteringEnabled">true</bool>
      <string name="Name">Workspace</string>
    </Properties>
    <Item class="Part" referent="RBX1">
      <Properties>
        <bool name="Anchored">true</bool>
        <string name="Name">Baseplate</string>
        <CoordinateFrame name="CFrame"><X>0</X><Y>-4</Y><Z>0</Z><R00>1</R00><R01>0</R01><R02>0</R02><R10>0</R10><R11>1</R11><R12>0</R12><R20>0</R20><R21>0</R21><R22>1</R22></CoordinateFrame>
        <Vector3 name="size"><X>512</X><Y>8</Y><Z>512</Z></Vector3>
        <Color3uint8 name="Color3uint8">4288716960</Color3uint8>
      </Properties>
    </Item>
    <Item class="SpawnLocation" referent="RBX2">
      <Properties>
        <bool name="Anchored">true</bool>
        <string name="Name">SpawnLocation</string>
        <CoordinateFrame name="CFrame"><X>0</X><Y>0.5</Y><Z>0</Z><R00>1</R00><R01>0</R01><R02>0</R02><R10>0</R10><R11>1</R11><R12>0</R12><R20>0</R20><R21>0</R21><R22>1</R22></CoordinateFrame>
        <Vector3 name="size"><X>12</X><Y>1</Y><Z>12</Z></Vector3>
      </Properties>
    </Item>
  </Item>
</roblox>
EOF
echo "wrote $DEST/server.rbxl ($(wc -c < "$DEST/server.rbxl") bytes)"

cd Clients/OffBlox

xvfb-run wine OffBlox.exe -task StartServer -placeId 9000000000019 -universeId 9000000000018 -port 25565 -creatorId 62884268 -creatorType 0 -placeVersion 0 -numTestServerPlayersUponStartup 0 -parentPid 8740 -parentSessionGuid 7BA89D0A-63AA-4500-B7FB-2293D4AF34C0 -instanceId StudioServer