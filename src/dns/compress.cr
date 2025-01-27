module DNS::Compress
  enum PointerFlag : UInt8
    BadLength      = 0_u8
    InvalidPointer = 1_u8
    OffsetZero     = 2_u8
    Successed      = 4_u8
  end

  enum ChunkFlag : UInt8
    BadLength        = 0_u8
    IndexOutOfBounds = 1_u8
    Pointer          = 2_u8
    Successed        = 3_u8
  end

  def self.decode!(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : String
    offset_buffer = uninitialized UInt8[1_i32]
    temporary = IO::Memory.new

    loop do
      raise Exception.new String.build { |io| io << "Compress.decode!: Packet size (" << temporary.size << ") is greater than Options.packet.maximumSizeOfPacket (" << options.packet.maximumSizeOfPacket << ")." } if temporary.size > options.packet.maximumSizeOfPacket

      read_length = io.read offset_buffer.to_slice
      temporary.write offset_buffer.to_slice
      break if offset_buffer.to_slice[0_i32].zero?

      if 0b00000011 == (offset_buffer.to_slice[0_i32] >> 6_i32)
        read_length = io.read offset_buffer.to_slice
        temporary.write offset_buffer.to_slice

        break
      end

      copy_length = IO.copy io, temporary, offset_buffer.to_slice[0_i32]
      break if copy_length != offset_buffer.to_slice[0_i32]
    end

    before_buffer_pos = buffer.pos
    buffer.write temporary.to_slice

    depth_decode_by_pointer! protocol_type: protocol_type, buffer: buffer, offset: before_buffer_pos, options: options
  end

  def self.decode_by_pointer!(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new, allow_empty : Bool = false) : String
    pointer_header_buffer = uninitialized UInt8[1_i32]
    read_length = io.read pointer_header_buffer.to_slice
    raise Exception.new "Compress.decode_by_pointer!: Failed to read 1 Bytes from IO, The pointer header is 1 Bytes." if 1_i32 != read_length
    buffer.write pointer_header_buffer.to_slice[0_i32, read_length]
    return String.new if pointer_header_buffer.to_slice[0_i32].zero? && allow_empty

    pointer_flag = pointer_header_buffer.to_slice[0_i32]
    raise Exception.new "Compress.decode_by_pointer!: The first two high bits of the pointer must be 1." if 0b00000011 != (pointer_flag >> 6_i32)

    pointer_offset_buffer = uninitialized UInt8[1_i32]
    read_length = io.read pointer_offset_buffer.to_slice
    raise Exception.new "Compress.decode_by_pointer!: Failed to read 1 Bytes from IO, The pointer offset is 1 Bytes." if 1_i32 != read_length
    buffer.write pointer_offset_buffer.to_slice[0_i32, read_length]

    offset = pointer_offset_buffer.to_slice[0_i32]
    offset = ((pointer_flag - 0b11000000).to_i32 << 8_u8) | offset
    offset += 2_i32 if protocol_type.tcp? || protocol_type.tls?
    raise Exception.new "Compress.decode_by_pointer!: Decoding failed or the offset value is zero!" if offset.zero?
    raise Exception.new "Compress.decode_by_pointer!: The offset value is greater than the buffer size, Offset index out Of bounds!" if offset > buffer.size

    depth_decode_by_pointer! protocol_type: protocol_type, buffer: buffer, offset: offset, options: options
  end

  def self.decode_by_length!(protocol_type : ProtocolType, io : IO, length : UInt16, buffer : IO::Memory, options : Options = Options.new, maximum_length : UInt16 = 512_u16) : String
    raise Exception.new String.build { |io| io << "Compress.decode_by_length!: The length (" << length << ") to be read is greater than the maximum preset value (" << maximum_length << ")." } if length > maximum_length

    begin
      temporary = IO::Memory.new length
      IO.copy io, temporary, length
      temporary.rewind
    rescue ex
      raise Exception.new String.build { |io| io << "Compress.decode_by_length!: Because: (" << ex.message << ")." }
    end

    before_buffer_pos = buffer.pos

    begin
      buffer.write temporary.to_slice
    rescue ex
      raise Exception.new String.build { |io| io << "Compress.decode_by_length!: Because: (" << ex.message << ")." }
    end

    depth_decode_by_pointer! protocol_type: protocol_type, buffer: buffer, offset: before_buffer_pos, options: options
  end

  def self.encode_chunk_string(io : IO, value : String)
    return io.write Bytes[0_u8] if value.empty?

    parts = value.split '.'
    parts.pop if parts.last.empty?

    parts.each do |part|
      io.write_bytes part.size.to_u8
      io << part
    end

    io.write Bytes[0_i32]
  end

  private def self.depth_decode_by_pointer!(protocol_type : ProtocolType, buffer : IO::Memory, offset : Int, options : Options = Options.new) : String
    before_buffer_pos = buffer.pos
    buffer.pos = offset

    chunk_list = [] of Array(String)
    depth = options.packet.maximumDepthOfCanonicalName.dup

    while !(depth -= 1_i32).zero?
      flag, chunk_parts, chunk_size = decode_chunk! buffer: buffer, options: options
      chunk_list << chunk_parts unless chunk_parts.empty?

      if flag.successed?
        buffer.pos = before_buffer_pos
        return chunk_list.flatten.join '.'
      end

      if flag.pointer?
        next update_chunk_pointer_position protocol_type: protocol_type, buffer: buffer, chunk_size: chunk_size
      end

      buffer.pos = before_buffer_pos

      break
    end

    raise Exception.new String.build { |io| io << "Compress.depth_decode_by_pointer!: After " << options.packet.maximumDepthOfCanonicalName << " attempts to decode the chunk, it still fails, and the chunk depth exceeds the preset value!" }
  end

  private def self.decode_chunk!(buffer : IO::Memory, options : Options = Options.new) : Tuple(ChunkFlag, Array(String), UInt8)
    chunk_parts = [] of String

    loop do
      chunk_length_buffer = uninitialized UInt8[1_i32]
      read_length = buffer.read chunk_length_buffer.to_slice
      chunk_size = chunk_length_buffer.to_slice[0_i32]

      return Tuple.new ChunkFlag::BadLength, chunk_parts, chunk_size if 1_i32 != read_length
      break if chunk_size.zero?

      if 0b00000011 == (chunk_size >> 6_i32)
        return Tuple.new ChunkFlag::Pointer, chunk_parts, chunk_size
      end

      if chunk_size > buffer.size
        return Tuple.new ChunkFlag::IndexOutOfBounds, chunk_parts, chunk_size
      end

      raise Exception.new String.build { |io| io << "Compress.decode_chunk!: chunk_size (" << chunk_size << ") is greater than Options.packet.maximumSizeOfPerChunk (" << options.packet.maximumSizeOfPerChunk << ")." } if chunk_size > options.packet.maximumSizeOfPerChunk
      temporary = IO::Memory.new chunk_size
      copy_length = IO.copy buffer, temporary, chunk_size

      return Tuple.new ChunkFlag::BadLength, chunk_parts, chunk_size if copy_length.zero?
      chunk_parts << String.new temporary.to_slice[0_i32, copy_length]
    end

    Tuple.new ChunkFlag::Successed, chunk_parts, 0_u8
  end

  private def self.update_chunk_pointer_position(protocol_type : ProtocolType, buffer : IO::Memory, chunk_size : UInt8)
    offset_buffer = uninitialized UInt8[1_i32]
    read_length = buffer.read offset_buffer.to_slice
    return PointerFlag::BadLength if 1_i32 != read_length

    # References: A warm welcome to DNS - https://powerdns.org/hello-dns/basic.md.html
    # In this case, the DNS name of the answer is encoded is 0xc0 0x0c.
    # The c0 part has the two most significant bits set, indicating that the following 6+8 bits are a pointer to somewhere earlier in the message.
    # In this case, this points to position 12 (= 0x0c) within the packet, which is immediately after the DNS header.
    # There we find 'www.ietf.org'.
    # Note: (pointer 6bits + offset 8bits)

    offset = offset_buffer.to_slice[0_i32]
    offset = ((chunk_size - 0b11000000).to_i32 << 8_u8) | offset
    return PointerFlag::OffsetZero if offset.zero?
    return PointerFlag::BadLength if offset > buffer.size

    before_buffer_pos = buffer.pos
    buffer.pos = offset
    buffer.pos += 2_i32 if protocol_type.tcp? || protocol_type.tls?

    PointerFlag::Successed
  end
end
