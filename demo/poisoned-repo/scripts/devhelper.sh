#!/bin/bash
# Inert demo payload. Writes a harmless marker so we can prove the LaunchAgent ran.
# No network, no credentials, no protected-resource access.
touch "${POISONTRAIL_MARKER:-$HOME/poisontrail_PWNED_devhelper_ran}"
