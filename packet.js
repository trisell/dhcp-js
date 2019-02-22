/**
 * Base Code from https://github.com/song940/node-dhcp
 * [Packet description]
 * https://tools.ietf.org/html/rfc2131
 * https://tools.ietf.org/html/rfc2132
 * https://www.iana.org/assignments/bootp-dhcp-parameters
 */

function Packet(){
  this.op    = 0;
  this.htype = 0;
  this.hlen  = 0;
  this.hops  = 0;
  this.xid   = 0;
  this.secs  = 0;
  this.flags = 0;
  return this;
}

Packet.prototype.toBuffer = function(){
  const buffer = new Buffer(1);
  buffer.write(this.op);
  return buffer;
};

Packet.OPCODE = {
  BOOTREQUEST: 0x01,
  BOOTREPLY  : 0x02
};

Packet.TYPES = {
  // rfc2132
  DHCPDISCOVER        : 0x01,
  DHCPOFFER           : 0x02,
  DHCPREQUEST         : 0x03,
  DHCPDECLINE         : 0x04,
  DHCPACK             : 0x05,
  DHCPNAK             : 0x06,
  DHCPRELEASE         : 0x07,
  DHCPINFORM          : 0x08,
  // rfc3203
  DHCPFORCERENEW      : 0x09,
  // rfc4388
  DHCPLEASEQUERY      : 0x10,
  DHCPLEASEUNASSIGNED : 11,
  DHCPLEASEUNKNOWN    : 12,
  DHCPLEASEACTIVE     : 13,
  // rfc6296
  DHCPBULKLEASEQUERY  : 14,
  DHCPLEASEQUERYDONE  : 15,
  // rfc7724
  DHCPACTIVELEASEQUERY: 16,
  DHCPLEASEQUERYSTATUS: 17,
  DHCPTLS             : 18
};

function ipv4(data){
  return [
    data[0],
    data[1],
    data[2],
    data[3]
  ].join('.');
}

function mac(data){
  return [].slice.call(data).filter(function(c){
    return !!c;
  }).map(function(c){
    return c.toString(16);
  }).join(':');
}

function str(data){
  return data.toString().replace(/\u0000/g, '');
}

Packet.Options = {

  //Subnet Mask
  1: function(data){
    return {
      SubnetMask: ipv4(data)
    }
  },
  // Time Offset
  2: function(data){
    return {
      TimeOffset: parseInt(data)
    }
  },
  // Router Option
  3: function(data){
    return {
      Router: ipv4(data)
    }
  },
  // Time Server Option
  4: function(data){
    return {
      TimeServer: ipv4(data)
    }
  },
  // Name Server Option
  5: function(data){
    return {
      NameServer: ipv4(data)
    }
  },
  // DNS Option
  6: function(data){
    return {
      DNS: ipv4(data)
    };
  },
  // Log Server
  7: function(data){
    return {
      LogServer: ipv4(data)
    }
  },
  // Cookie Server
  8: function(data){
    return {
      CookieServer: ipv4(data)
    }
  },
  // LPR Server
  9: function(data){
    return {
      LPRServer: ipv4(data)
    }
  },
  // Impress Server
  10: function(data){
    return {
      ImpressServer: ipv4(data)
    }
  },
  // ResourceLocation Server
  11: function(data){
    return {
      ResourceLocationServer: ipv4(data)
    }
  },
  // Host Name
  12: function(data) {
    return {
      HostName: data.toString()
    };
  },
  // Boot File Size
  13: function(data){
    return {
      SubnetMask: data.readUInt16BE(0)
    }
  },
  // Merit Dump File
  14: function(data){
    return {
      SubnetMask: data.toString()
    }
  },
  // Domain Name
  15: function(data){
    return {
      DomainName: data.toString()
    };
  },
  // Swap Server
  16: function(data){
    return {
      SwapServer: ipv4(data)
    }
  },
  // Root Path
  17: function(data){
    return {
      RootPath: data.toString()
    };
  },
  //Extensions Path
  18: function(data){
    return {
      ExtensionPath: data.toString()
    }
  },
  // IP Forwarding Enable/Disable
  19: function(data){
    return {
      IPForwarding: data.readUIntBE() == 1
    }
  }, 
  // Non-Local Source Routing Enable/Disable
  20: function(data){
    return {
      LocalSourceRouting: data.readUIntBE() == 1
    }
  },
  // Policy Filter
  21: function(data){
    return {
      PolicyFilter: ipv4(data)
    };
  },
  //  Maximum Datagram Reassembly Size
  22: function(data){
    return {
      TimeOffset: data.readUInt16BE()
    }
  },
  // Default IP Tiime-to-live
  23: function(data){
    return {
      IPTime2Live: data.readUInt8()
    }
  },
  // Path MTU Aging Timeout Option
  24: function(data){
    return {
      MTUAgingTimeout: data.readUInt32BE()
    }
  },
  25: function(data){
    return {
      TimeOffset: data.readUInt16BE()
    }
  },
  // Interface MTU
  26: function(data){
    return {
      InterfaceMTU: data.readUInt16BE()
    }
  },
  // All Subnets are Local
  27: function(data){
    return {
      SubnetsLocal: data.readUIntBE() == 1
    }
  },
  // Broadcast Address
  28: function(data){
    return {
      BroadcastAddress: ipv4(data)
    }
  },
  // Perform Mask Discovery
  29: function(data){
    return {
      MaskDiscovery: data.readUIntBE() == 1
    }
  },
  // Mask Supplier
  30: function(data){
    return {
      MaskSupplier: data.readUIntBE() == 1
    }
  },
  // Perform Router Discovery
  31: function(data){
    return {
      RouterDiscovery: data.readUIntBE() == 1
    }
  },
  // Router Solicitation Address
  32: function(data){
    return {
      RouterSolAddress: ipv4(data)
    }
  },
  // Static Route
  33: function(data){
    return {
      StaticRoute: ipv4(data)
    }
  },
  // Trailer Encapsulation
  34: function(data){
    return {
      TrailerEncapsulation: data.readUIntBE() == 1
    }
  },
  // ARP Cache Timeout
  35: function(data){
    return {
      ARPCacheTimeout : data.readUInt32BE()
    }
  },
  // Ethernet Encapsulation
  36: function(data){
    return {
      EtherNetEncapsulation: data.readUIntBE() == 1
    }
  },
  // TCP Default TTL 
  37: function(data){
    return {
      TCPDefaultTTL: data.readUInt8()
    }
  },
  // TCP Keepalive Interval
  38: function(data){
    return {
      TCPKeepalive: data.readUInt32BE()
    }
  }, 
  // TCP Keepalive Garbage
  39: function(data){
    return {
      TCPKeepaliveGarbage: data.readInt32BE()
    }
  },
  // Network Infomation Sevice Domain
  40: function(data){
    return {
      NetworkInforService: data.toString()
    }
  },
  // Network Information Servers
  41: function(data){
    return {
      NetworkInfoServer: ipv4(data)
    }
  },
  // Network Time Protocol Servers
  42: function(data){
    return {
      NTPServers: ipv4(data)
    }
  },
  // Vendor Specific Information Need to read RFC
  43: function(data){
    return {
      VendorSpecificInfo: data.toString()
    }
  },
  // NetBIOS over TCP/IP Name Server
  44: function(data){
    return {
      NetBIOSNameServer: ipv4(data)
    }
  },
  // NetBios over TCP/IP Datagram Distriibution Server
  45: function(data){
    return {
      NetBiosDDServer: ipv4(data)
    }
  },
  // NetBIOS over TCP/IP Node Type Need to read RFC
  46: function(data){
    return {
      NetBIOSNodeType: data.toString()
    }
  },
  // NetBIOS over TCP/IP Scope 
  47: function(data){
    return {
      NetBIOSScope: data.toString()
    }
  },
  // XWindow System Font Server
  48: function(data){
    return {
      XWindowSFServer: ipv4(data)
    }
  },
  // X Window System Display Manger
  49: function(data){
    return {
      XWindowSystemDisplayManager: ipv4(data)
    }
  },
  // Requested IP Address 
  50: function(data){
      return {
        RequestedIPAddress: ipv4(data)
      };
  },
  // IP Address Lease Time
  51: function(data){
    return {
      LeaseTime: data.readUInt32BE()
    };
  },
  // Option Overload Need to read RFC
  52: function(data){
    return {
      OptionOverload: data.toString()
    }
  },
  // DHCP Message Type
  53: function(data){
    return {
      MessageType: data.readUInt8()
    };
  },
  // Server Identifier
  54: function(data){
    return {
      ServerIdentifier: ipv4(data)
    };
  },
  // Parameter REquest List  Read RFC
  55: function(data){
    return {
      Parameters: data.toString()
    };
  },
  // Message Read RFC
  56: function(data){
    return {
      Message: str(data)
    };
  },
  // Maximum DHCP Message Size  Read RFC
  57: function(data){
    return {
      MaxDHCPMessage: data.toString()
    }
  },
  // Renewal (T1) Time Value
  58: function(data){
    return {
      RenewalTime: data.readUInt32BE()
    };
  },
  // Rebinding (T2) Time Value
  59: function(data){
    return {
      RebindingTime: data.readUInt32BE()
    };
  },
  // Vendor Class Indentifier
  60: function(data){
    return {
      VendorClass: data.toString()
    };
  },
  // Client Identifier
  61: function(data){
    return {
      ClientIdentifier: data.readUInt32BE()
    }
  },
  81: function(data){
    return {
      ClientFQDN: data.toString()
    };
  }
  
};

/**
 * [parse description]
 * @param  {[type]} msg [description]
 * @return {[type]}     [description]
 */
Packet.parse = function(msg){
  var packet = new Packet();
  packet.op      = msg.readUInt8(0);
  packet.htype   = msg.readUInt8(1);
  packet.hlen    = msg.readUInt8(2);
  packet.hops    = msg.readUInt8(3);
  packet.xid     = msg.readUInt32BE(4);
  packet.secs    = msg.readUInt16BE(8);
  packet.flags   = msg.readUInt16BE(10);
  packet.ciaddr  = ipv4(msg.slice(12, 12+4));
  packet.yiaddr  = ipv4(msg.slice(16, 16+4));
  packet.siaddr  = ipv4(msg.slice(20, 20+4));
  packet.giaddr  = ipv4(msg.slice(24, 24+4));
  packet.chaddr  = mac(msg.slice(28, 28+16));
  packet.sname   = str(msg.slice(44, 44+64));
  packet.file    = str(msg.slice(108, 108+128));
  // The first four octets of the 'options' field of the DHCP message
  // contain the (decimal) values 99, 130, 83 and 99, respectively (this
  // is the same magic cookie as is defined in RFC 1497 [17]).
  packet.magicCookie = msg.slice(236, 236+4);
  packet.options = [];
  var pos = 240, ended, type, length, data;
  while(!ended && pos < msg.length){
    type = msg[pos++];
    console.log(type);
    switch (type) {
      case 0x00: pos++;        break; // rfc2132#section-3.1
      case 0xff: ended = true; break; // rfc2132#section-3.2
      default:
        length = msg.readUInt8(pos++);
        data = msg.slice(pos, pos = pos + length);
        const option = Packet.Options[type](data);
        packet.options.push(Object.assign({ type, data }, option));
    }
  };
  return packet;
};

module.exports = Packet;