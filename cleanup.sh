#!/bin/bash

echo "Starting safe cleanup..."

rm -rf ~/.cache
rm -rf ~/.templateengine
rm -rf ~/.motd_shown
rm -rf ~/.wget-hsts

rm -rf ~/.aspnet
rm -rf ~/.dotnet
rm -rf ~/.nuget

rm -rf ~/.local/share/Trash/*

echo "Cleanup complete!"
