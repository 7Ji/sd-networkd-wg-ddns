---
SPDX-License-Identifier: AGPL-3.0-or-later
---
# Systemd-networkd wireguard netdev endpoints DynDNS updater 

## Build & Install
### AUR
An AUR package is maintained at https://aur.archlinux.org/packages/sd-networkd-wg-ddns , you can just build and install it by yourself, or use your favorite AUR helper.
### Manual
#### Build
This package needs no build-time dependencies other than a good c compiler, just run `make`
```
make
```
#### Install
If you want to install to a target "root" dir:
```
make install DESTDIR=YOUR_TARGET_ROOT
```
Or if you want to install to your real root:
```
sudo make install
```
## Usage
### Manual
```
sd-networkd-wg-ddns (--interval/-i [interval]) [netdev name] ([netdev name] ([netdev name] ...))
  --interval/-i [interval] set the interval between each check
  [netdev name]            netdev names under '/etc/systemd/network', without .netdev suffix
```
Example:
```
sd-networkd-wg-ddns --interval 1 30-wireguard-company 40-wiregard-personal
```
This means to read netdev configs `/etc/systemd/network/30-wireguard-company.netdev` and `/etc/systemd/network/40-wireguard-personal.netdev`, then watch for the network interfaces they defined, checking for any peers with an endpoint with a domain name as host. With a 1-second interval, compare the address on interface and the one resolved from domain, and update them should they differ.

### Systemd
Before using the systemd unit, configure its arguments in `/etc/conf.d/sd-networkd-wg-ddns:
```
SD_NETWORKD_WG_DDNS_ARGS="--interval 1 30-wireguard-company 40-wiregard-personal"
```
Then enable and start the bundled `sd-networkd-wg-ddns.service`:
```
sudo systemctl enable --now sd-networkd-wg-ddns.service
```

## License
**sd-networkd-wg-ddns**, systemd-networkd wireguard netdev endpoints DynDNS updater 

Copyright (C) 2024-present Guoxin "7Ji" Pu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
