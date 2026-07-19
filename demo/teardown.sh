#!/usr/bin/env bash
# Remove any LaunchAgent / markers created during a live (allowed) demo run.
launchctl bootout "gui/$(id -u)/com.acme.devhelper" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/com.acme.devhelper.plist"
rm -f "$HOME/poisontrail_PWNED_devhelper_ran"
echo "[*] Demo LaunchAgent and markers removed."
