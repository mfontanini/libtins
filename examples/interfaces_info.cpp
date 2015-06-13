/*
 * Copyright (c) 2015, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string>
#include <iostream>
#include <tins/network_interface.h>

using namespace Tins;
using namespace std;

int main() {
	// Get all interfaces and iterate over them.
	for (const NetworkInterface& iface : NetworkInterface::all()) {
		// Get the name of this interface
		string name = iface.name();

		// "stringify" the status of the interface
		string status = iface.is_up() ? "up" : "down";
		
		// Get this interface's information (addresses).
		NetworkInterface::Info info = iface.info();
		
		// Now print all of this info.
		cout << name << ": " << endl;
		cout << "   HW address:  " << info.hw_addr << endl
			 << "   IP address:  " << info.ip_addr << endl
			 << "   Netmask:     " << info.netmask << endl
			 << "   Broadcast:   " << info.bcast_addr << endl 
			 << "   Iface index: " << iface.id() << endl
			 << "   Status:      " << "interface " << status << endl << endl;
	}
}