# -------------------------------------------------------------------------- #
# Copyright 2002-2016, OpenNebula Project, OpenNebula Systems                #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License"); you may    #
# not use this file except in compliance with the License. You may obtain    #
# a copy of the License at                                                   #
#                                                                            #
# http://www.apache.org/licenses/LICENSE-2.0                                 #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#--------------------------------------------------------------------------- #

require 'opennebula/x509_auth'

module X509CloudAuth

    # Gets the username associated with a password for x509 driver
    # It matches the  password with each of the pipe-separated DNs stored
    # in USER/PASSWORD
    def get_username(password)
      select_username(password) { |u, p|
        u["AUTH_DRIVER"] == "x509" && u["PASSWORD"].split('|').include?(p)
      }
    end

    def do_auth(env, params={})
        # For https, the web service should be set to include the user cert in
        # the environment.
        cert_line   = env['HTTP_SSL_CLIENT_CERT']
        cert_line   = nil if cert_line == '(null)' # For Apache mod_ssl

        if cert_line.nil?
            return nil
        end

        # Use the https credentials for authentication
        begin
            m      = cert_line.match(/(-+BEGIN CERTIFICATE-+)([^-]*)(-+END CERTIFICATE-+)/)
            cert_s = "#{m[1]}\n#{m[2].gsub(' ',"").scan(/.{1,64}/).join("\n")}\n#{m[3]}"
            cert   = OpenSSL::X509::Certificate.new(cert_s)
        rescue
            raise "Could not create X509 certificate from " + cert_line
        end

        # Call an external program to resolve the certificate to a username
        username = %x("opennebula-user-cert" "#{cert_s}").chomp()
        if username == ""
            username = nil
        end

        return username if username

        return nil
    end
end
