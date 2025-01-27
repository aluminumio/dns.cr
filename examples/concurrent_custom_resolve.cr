require "../src/dns.cr"

# In this example, we use concurrent to custom resolve.
# You can even use `DNS::Resolver::Options` to adjust as needed.
# We can query the results through UDP, TCP and TLS.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32)
dns_servers << DNS::Address::TCP.new ipAddress: Socket::IPAddress.new("8.8.4.4", 53_i32)
dns_servers << DNS::Address::TLS.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32)
dns_resolver = DNS::Resolver.new dnsServers: dns_servers, options: DNS::Options.new

concurrent_mutex = Mutex.new :unchecked
concurrent_fibers = Set(Fiber).new
reply_mutex = Mutex.new :unchecked
reply_packets = Set(Tuple(String, Time::Span, Tuple(DNS::FetchType, Array(DNS::Packet)))).new

main_concurrent_fibers = spawn do
  google_query_fiber = spawn do
    before = Time.local
    ask_packet = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "8.8.8.8.in-addr.arpa", record_type: DNS::Packet::RecordFlag::PTR, class_type: DNS::Packet::ClassFlag::Internet
    packets = dns_resolver.resolve host: "8.8.8.8.in-addr.arpa", record_type: DNS::Packet::RecordFlag::PTR, ask_packet: ask_packet
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "8.8.8.8.in-addr.arpa", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << google_query_fiber }

  cloudflare_query_fiber = spawn do
    before = Time.local
    ask_packet = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "cloudflare.com", record_type: DNS::Packet::RecordFlag::SOA, class_type: DNS::Packet::ClassFlag::Internet
    packets = dns_resolver.resolve host: "cloudflare.com", record_type: DNS::Packet::RecordFlag::SOA, ask_packet: ask_packet
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "cloudflare.com", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << cloudflare_query_fiber }

  spotify_query_fiber = spawn do
    before = Time.local
    ask_packet = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "spotify.com", record_type: DNS::Packet::RecordFlag::CNAME, class_type: DNS::Packet::ClassFlag::Internet
    packets = dns_resolver.resolve host: "spotify.com", record_type: DNS::Packet::RecordFlag::CNAME, ask_packet: ask_packet
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "spotify.com", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << spotify_query_fiber }

  github_query_fiber = spawn do
    before = Time.local
    ask_packet = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "github.com", record_type: DNS::Packet::RecordFlag::MX, class_type: DNS::Packet::ClassFlag::Internet
    packets = dns_resolver.resolve host: "github.com", record_type: DNS::Packet::RecordFlag::MX, ask_packet: ask_packet
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "github.com", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << github_query_fiber }

  medium_query_fiber = spawn do
    before = Time.local
    ask_packet = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "medium.com", record_type: DNS::Packet::RecordFlag::TXT, class_type: DNS::Packet::ClassFlag::Internet
    packets = dns_resolver.resolve host: "medium.com", record_type: DNS::Packet::RecordFlag::TXT, ask_packet: ask_packet
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "medium.com", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << medium_query_fiber }

  another_github_query_fiber = spawn do
    before = Time.local
    ask_packet = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "github.com", record_type: DNS::Packet::RecordFlag::MX, class_type: DNS::Packet::ClassFlag::Internet
    packets = dns_resolver.resolve host: "github.com", record_type: DNS::Packet::RecordFlag::MX, ask_packet: ask_packet
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "github.com", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << another_github_query_fiber }
end

concurrent_mutex.synchronize { concurrent_fibers << main_concurrent_fibers }

loop do
  all_dead = concurrent_mutex.synchronize { concurrent_fibers.all? { |fiber| fiber.dead? } }
  next sleep 0.25_f32.seconds unless all_dead

  reply_mutex.synchronize do
    STDOUT.puts reply_packets.map { |tuple| Tuple.new tuple.first, tuple.last }
    STDOUT.puts reply_packets.map { |tuple| Tuple.new tuple.first, tuple[1_i32] }
  end

  break
end
