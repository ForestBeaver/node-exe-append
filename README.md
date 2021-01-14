exe-append
==========

Appends arbitrary data to signed Windows executables. This is done by embedding
the data at the end of the digital certificate section.

This method is described in more detail in this blog post:
http://blog.barthe.ph/2009/02/22/change-signed-executable/


Installing
----------

    npm install exe-append


Using
-----

    const exe = require("exe-append");
    const buffer = exe.append(fs.readFileSync("my.exe"), "arbirarty data");
