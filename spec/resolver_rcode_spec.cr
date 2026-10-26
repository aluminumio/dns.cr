require "./spec_helper"

# A loopback UDP server that answers every query with a fixed rcode, and
# with one A record (192.0.2.1) when `answer` is true. With `reply: false`
# it reads queries and never answers, which is a timeout to the client.
class StubDNSServer
  getter socket : UDPSocket
  getter queries = 0

  def initialize(@rcode : UInt8 = 0_u8, @answer : Bool = false, @reply : Bool = true)
    @socket = UDPSocket.new
    @socket.bind "127.0.0.1", 0
    spawn { serve }
  end

  def address : DNS::Address::UDP
    DNS::Address::UDP.new ipAddress: socket.local_address, timeout: DNS::TimeOut.new(read: 200.milliseconds, write: 1.second, connect: 1.second)
  end

  def close
    socket.close rescue nil
  end

  private def serve
    buffer = Bytes.new 512
    loop do
      length, client = socket.receive buffer
      @queries += 1
      next unless @reply
      socket.send reply_for(buffer[0, length]), to: client
    end
  rescue IO::Error
  end

  private def reply_for(query : Bytes) : Bytes
    io = IO::Memory.new
    io.write query[0, 2]                                         # transaction id
    io.write_bytes 0x8180_u16 | @rcode, IO::ByteFormat::BigEndian # QR, RD, RA, rcode
    io.write_bytes 1_u16, IO::ByteFormat::BigEndian              # QDCOUNT
    io.write_bytes (@answer ? 1_u16 : 0_u16), IO::ByteFormat::BigEndian
    io.write_bytes 0_u16, IO::ByteFormat::BigEndian
    io.write_bytes 0_u16, IO::ByteFormat::BigEndian
    io.write query[12, query.size - 12] # question, as asked
    if @answer
      io.write_bytes 0xC00C_u16, IO::ByteFormat::BigEndian # name: pointer to the question
      io.write_bytes 1_u16, IO::ByteFormat::BigEndian      # A
      io.write_bytes 1_u16, IO::ByteFormat::BigEndian      # IN
      io.write_bytes 300_u32, IO::ByteFormat::BigEndian    # TTL
      io.write_bytes 4_u16, IO::ByteFormat::BigEndian
      io.write Bytes[192, 0, 2, 1]
    end
    io.to_slice
  end
end

private def resolve_with(server : StubDNSServer, concurrent : Bool = true, host : String = "example.test")
  options = DNS::Options.new
  options.addrinfo.concurrentQuery = concurrent
  resolver = DNS::Resolver.new dnsServers: Set{server.address.as(DNS::Address)}, options: options
  ask = DNS::Packet.create_query_packet protocol_type: DNS::ProtocolType::UDP, name: host, record_type: DNS::Packet::RecordFlag::A
  {resolver, resolver.resolve_with_rcode(host: host, record_type: DNS::Packet::RecordFlag::A, ask_packet: ask)}
end

describe "DNS::Resolver#resolve_with_rcode" do
  [true, false].each do |concurrent|
    context concurrent ? "concurrent query" : "regular query" do
      it "gives NoError and the packets for NOERROR with answers" do
        server = StubDNSServer.new rcode: 0_u8, answer: true
        _, result = resolve_with server, concurrent
        fetch_type, packets, rcode = result
        server.close

        fetch_type.should eq DNS::FetchType::Remote
        rcode.should eq DNS::Packet::ErrorFlag::NoError
        packets.size.should eq 1
        packets.first.answers.size.should eq 1
      end

      it "gives NoError and a packet with no answers for NOERROR empty" do
        server = StubDNSServer.new rcode: 0_u8
        _, result = resolve_with server, concurrent
        _, packets, rcode = result
        server.close

        rcode.should eq DNS::Packet::ErrorFlag::NoError
        packets.size.should eq 1
        packets.first.answers.should be_empty
      end

      it "gives NameError and no packets for NXDOMAIN" do
        server = StubDNSServer.new rcode: 3_u8
        _, result = resolve_with server, concurrent
        _, packets, rcode = result
        server.close

        rcode.should eq DNS::Packet::ErrorFlag::NameError
        packets.should be_empty
      end

      it "gives ServerFailure and no packets for SERVFAIL" do
        server = StubDNSServer.new rcode: 2_u8
        _, result = resolve_with server, concurrent
        _, packets, rcode = result
        server.close

        rcode.should eq DNS::Packet::ErrorFlag::ServerFailure
        packets.should be_empty
      end

      it "gives Refused and no packets for REFUSED" do
        server = StubDNSServer.new rcode: 5_u8
        _, result = resolve_with server, concurrent
        _, packets, rcode = result
        server.close

        rcode.should eq DNS::Packet::ErrorFlag::Refused
        packets.should be_empty
      end

      it "gives nil and no packets when the server does not reply" do
        server = StubDNSServer.new reply: false
        _, result = resolve_with server, concurrent
        _, packets, rcode = result
        server.close

        rcode.should be_nil
        packets.should be_empty
      end
    end
  end

  it "still retries a non-NOERROR reply as before (1 + maximumNumberOfMismatchRetries sends)" do
    server = StubDNSServer.new rcode: 2_u8
    resolve_with server
    server.close

    server.queries.should eq 1 + DNS::Options.new.addrinfo.maximumNumberOfMismatchRetries
  end

  it "caches NOERROR and gives NoError from the cache" do
    server = StubDNSServer.new rcode: 0_u8, answer: true
    resolver, _ = resolve_with server
    ask = DNS::Packet.create_query_packet protocol_type: DNS::ProtocolType::UDP, name: "example.test", record_type: DNS::Packet::RecordFlag::A
    fetch_type, packets, rcode = resolver.resolve_with_rcode host: "example.test", record_type: DNS::Packet::RecordFlag::A, ask_packet: ask
    server.close

    fetch_type.should eq DNS::FetchType::Caching
    rcode.should eq DNS::Packet::ErrorFlag::NoError
    packets.size.should eq 1
    server.queries.should eq 1
  end

  it "does not cache a failure" do
    server = StubDNSServer.new rcode: 3_u8
    resolver, _ = resolve_with server
    ask = DNS::Packet.create_query_packet protocol_type: DNS::ProtocolType::UDP, name: "example.test", record_type: DNS::Packet::RecordFlag::A
    fetch_type, _, rcode = resolver.resolve_with_rcode host: "example.test", record_type: DNS::Packet::RecordFlag::A, ask_packet: ask
    server.close

    fetch_type.should eq DNS::FetchType::Remote
    rcode.should eq DNS::Packet::ErrorFlag::NameError
  end
end

describe "DNS::Resolver#resolve" do
  it "keeps its signature and gives only NOERROR packets" do
    server = StubDNSServer.new rcode: 2_u8
    options = DNS::Options.new
    resolver = DNS::Resolver.new dnsServers: Set{server.address.as(DNS::Address)}, options: options
    ask = DNS::Packet.create_query_packet protocol_type: DNS::ProtocolType::UDP, name: "example.test", record_type: DNS::Packet::RecordFlag::A
    result = resolver.resolve host: "example.test", record_type: DNS::Packet::RecordFlag::A, ask_packet: ask
    server.close

    result.should be_a Tuple(DNS::FetchType, Array(DNS::Packet))
    result[1].should be_empty
  end
end

describe "DNS::Resolver.reply_rcode" do
  it "prefers NOERROR, then NXDOMAIN, then the first other rcode; nil for no replies" do
    reply = ->(rcode : DNS::Packet::ErrorFlag) do
      packet = DNS::Packet.new arType: DNS::Packet::ARType::Reply, protocolType: DNS::ProtocolType::UDP
      packet.errorType = rcode
      packet
    end

    DNS::Resolver.reply_rcode([] of DNS::Packet).should be_nil
    DNS::Resolver.reply_rcode([reply.call(DNS::Packet::ErrorFlag::ServerFailure), reply.call(DNS::Packet::ErrorFlag::NoError)]).should eq DNS::Packet::ErrorFlag::NoError
    DNS::Resolver.reply_rcode([reply.call(DNS::Packet::ErrorFlag::Refused), reply.call(DNS::Packet::ErrorFlag::NameError)]).should eq DNS::Packet::ErrorFlag::NameError
    DNS::Resolver.reply_rcode([reply.call(DNS::Packet::ErrorFlag::Refused), reply.call(DNS::Packet::ErrorFlag::ServerFailure)]).should eq DNS::Packet::ErrorFlag::Refused
  end
end
