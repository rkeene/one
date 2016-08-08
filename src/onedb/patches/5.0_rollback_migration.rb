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

require 'nokogiri'

module OneDBPatch
    VERSION = "4.90.0"
    LOCAL_VERSION = "4.90.0"

    def is_hot_patch(ops)
        return false
    end

    def check_db_version(ops)
        db_version = read_db_version()

        if ( db_version[:version] != VERSION ||
             db_version[:local_version] != LOCAL_VERSION )

            raise <<-EOT
Version mismatch: patch file is for version
Shared: #{VERSION}, Local: #{LOCAL_VERSION}

Current database is version
Shared: #{db_version[:version]}, Local: #{db_version[:local_version]}
EOT
        end
    end

    def patch(ops)
        init_log_time()

        extra = Hash[ops[:extra].map{|e| e.split '='}]

        vm_id   = extra["vm_id"]
        host_id = extra["host_id"]

        raise "Required parameter: --extra vm_id=<vm_id>" if vm_id.nil? || vm_id.empty?
        raise "Required parameter: --extra host_id=<host_id>" if host_id.nil? || host_id.empty?

        hostname = @db[:host_pool].where(:oid => host_id).first[:name]

        @db.transaction do
            @db.fetch("SELECT * FROM vm_pool WHERE oid = #{vm_id}") do |row|
                doc = Nokogiri::XML(row[:body],nil,NOKOGIRI_ENCODING){|c| c.default_xml.noblanks}

                doc.root.at_xpath('STATE').content     = 8
                doc.root.at_xpath('LCM_STATE').content = 0

                doc.root.at_xpath('PREV_STATE').content     = 8
                doc.root.at_xpath('PREV_LCM_STATE').content = 0

                doc.root.at_xpath('HISTORY_RECORDS/HISTORY/HID').content = host_id
                doc.root.at_xpath('HISTORY_RECORDS/HISTORY/HOSTNAME').content = hostname
                doc.root.at_xpath('HISTORY_RECORDS/HISTORY/REASON').content = 2

                @db[:vm_pool].where(:oid => row[:oid]).update(:body => doc.root.to_s)
            end
        end

        @db.transaction do
            row = @db[:history].where(:vid=>vm_id).order(:seq).last
            doc = Nokogiri::XML(row[:body],nil,NOKOGIRI_ENCODING){|c| c.default_xml.noblanks}

            doc.root.at_xpath('HID').content      = host_id
            doc.root.at_xpath('HOSTNAME').content = hostname

            doc.root.at_xpath('REASON').content = 2

            doc.root.at_xpath('VM/STATE').content     = 8
            doc.root.at_xpath('VM/LCM_STATE').content = 0

            doc.root.at_xpath('VM/PREV_STATE').content     = 8
            doc.root.at_xpath('VM/PREV_LCM_STATE').content = 0

            @db[:history].where(:vid=>vm_id, :seq=>row[:seq]).update(:body => doc.root.to_s)
        end

        log_time()

        return true
    end
end
