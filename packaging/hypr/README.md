# No packaged Hyprland config

The SUPER+CTRL+A bind is registered at runtime by `password-manager
setup` (`integration/hyprland/keybind.py`), which writes
`~/.config/hypr/password-manager.conf` and prints the one `source = ...`
line for you to add to your own `hyprland.conf`. See `docs/USB_SETUP.md`.

Nothing is shipped here in the package itself -- there's no static
config to install system-wide, since the bind command
(`password-manager show`) doesn't vary per machine and the file it
writes lives in your user config, not `/usr/share`.
