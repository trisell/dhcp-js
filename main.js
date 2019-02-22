const dgram = require('dgram');
const server = dgram.createSocket("udp4");
const Packet = require('./packet');

const packet = new Packet;

console.log(packet);

server.on('error', function(err) {
  console.log(`server error:\n${err.stack}`);
});

server.on('message', function(msg, rinfo) {
  console.log(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
  let messagePacket = Packet.parse(msg);
  console.log(messagePacket);
});

server.on('listening', function() {
  const address = server.address();
  console.log(`server listening ${address.address}:${address.port}`);
});

server.bind(67);
