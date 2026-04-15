# -*- coding: binary -*-


module Msf

###
#
# Basic block_api stubs for Windows ARCH_X86 payloads
#
###
module Payload::Windows::BlockApi

  @block_api_iv = nil

  def block_api_iv
    @block_api_iv ||= rand(0x100000000)
  end

  def asm_block_api(opts={})
    @block_api_iv ||= rand(0x100000000)
    asm = Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'block_api.x86.graphml'),
      arch: ARCH_X86,
      name: 'api_call'
    )
    # Patch the assembly to set the correct IV
    # db 0xbf, 0x00, 0x00, 0x00, 0x00  =>  mov edi, <iv>
    iv_bytes = [block_api_iv].pack('V').bytes.map { |b| "0x%02x" % b }.join(', ')
    asm.sub!("db 0xbf, 0x00, 0x00, 0x00, 0x00", "db 0xbf, #{iv_bytes}")
    asm
  end

  def block_api_hash(mod, func)
    Rex::Text.block_api_hash(mod, func, iv: @block_api_iv)
  end

end
end
