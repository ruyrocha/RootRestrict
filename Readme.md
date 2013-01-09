RootRestrict
============

Restrict root access on Cpanel/WHM servers to known remote addresses:
no one will access your server, even if you root password was exposed.

Usage
-----

If you're using latest Cpanel/WHM Stable version, simply copy RootRestrict.pm
to /usr/local/cpanel/Cpanel/Security/Policy/RootRestrict.pm

You'll need to manually edit @allowed_ips and include your addresses, then
restart cpanel service.


