module DNS::Serialized
  abstract struct Address
    struct HTTPS < Address
      property ipAddress : String
      property timeout : TimeOut
      property tls : TransportLayerSecurity?
      property method : String
      property path : String
      property parameters : Array(Hash(String, String))?
      property headers : Array(Hash(String, String))?

      def initialize(@ipAddress : String = "8.8.8.8:53", @timeout : TimeOut = TimeOut.new, @method : String = "GET", @path : String = "/dns-query?dns=", @parameters : Array(Hash(String, String))? = nil, @headers : Array(Hash(String, String))? = nil)
      end

      def unwrap_uri_resource : String
        _parameters = parameters

        resource = String.build do |io|
          io << path

          if _parameters && !_parameters.empty?
            io << '?'
            _parameters.each { |entry| entry.each { |key, value| io << key << '=' << value << '&' } }
          end
        end

        resource.ends_with?('&') ? resource[0_i32..-2_i32] : resource
      end

      def unwrap_headers : ::HTTP::Headers
        _headers = ::HTTP::Headers.new
        headers.try &.each { |entry| entry.each { |tuple| _headers.add key: tuple.first, value: tuple.last } }

        _headers
      end

      def unwrap : DNS::Address?
        address, delimiter, port = ipAddress.rpartition ':'
        return unless _port = port.to_i?
        ip_address = Socket::IPAddress.new address: address, port: _port rescue nil
        return unless ip_address

        DNS::Address::HTTPS.new ipAddress: ip_address, timeout: timeout.unwrap, tls: tls.try &.unwrap, method: method, resource: unwrap_uri_resource, headers: unwrap_headers
      end
    end
  end
end
