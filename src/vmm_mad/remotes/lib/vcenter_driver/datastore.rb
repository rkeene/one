module VCenterDriver
require 'digest'
class DatastoreFolder
    attr_accessor :item, :items

    def initialize(item)
        @item = item
        @items = {}
    end

    ########################################################################
    # Builds a hash with Datastore-Ref / Datastore to be used as a cache
    # @return [Hash] in the form
    #   { ds_ref [Symbol] => Datastore object }
    ########################################################################
    def fetch!
        VIClient.get_entities(@item, "Datastore").each do |item|
            item_name = item._ref
            @items[item_name.to_sym] = Datastore.new(item)
        end

        VIClient.get_entities(@item, "StoragePod").each do |sp|
            @items[sp._ref.to_sym] = StoragePod.new(sp)
            VIClient.get_entities(sp, "Datastore").each do |item|
                item_name = item._ref
                @items[item_name.to_sym] = Datastore.new(item)
            end
        end
    end

    def monitor
        monitor = ""
        @items.values.each do |ds|
            monitor << "VCENTER_DS_REF=\"#{ds['_ref']}\"\n"
        end
        monitor
    end

    ########################################################################
    # Returns a Datastore or StoragePod. Uses the cache if available.
    # @param ref [Symbol] the vcenter ref
    # @return Datastore
    ########################################################################
    def get(ref)
        if !@items[ref.to_sym]
            if ref.start_with?("group-")
                rbvmomi_spod = RbVmomi::VIM::StoragePod.new(@item._connection, ref) rescue nil
                @items[ref.to_sym] = StoragePod.new(rbvmomi_spod)
            else
                rbvmomi_ds = RbVmomi::VIM::Datastore.new(@item._connection, ref) rescue nil
                @items[ref.to_sym] = Datastore.new(rbvmomi_ds)
            end
        end
        @items[ref.to_sym]
    end
end # class DatastoreFolder

class Storage
    attr_accessor :item

    include Memoize

    def self.new_from_ref(ref, vi_client)
        if ref.start_with?('group-')
            return VCenterDriver::StoragePod.new_from_ref(ref, vi_client)
        else
            return VCenterDriver::Datastore.new_from_ref(ref, vi_client)
        end
    end

    def self.get_image_import_template(ds_name, image_path, image_type, image_prefix, ipool, template_id)
        one_image = {}
        one_image[:template] = ""

        # Remove ds info from path
        image_path.sub!(/^\[#{ds_name}\] /, "")

        # Get image name
        file_name = File.basename(image_path).gsub(/\.vmdk$/,"")
        if template_id
            image_name = "#{file_name} - #{ds_name} [Template #{template_id}]"
        else
            image_name = "#{file_name} - #{ds_name}"
        end

        #Check if the image has already been imported
        image = VCenterDriver::VIHelper.find_by_name(OpenNebula::ImagePool,
                                                     image_name,
                                                     ipool,
                                                     false)
        if image.nil?
            #Set template
            one_image[:template] << "NAME=\"#{image_name}\"\n"
            one_image[:template] << "PATH=\"vcenter://#{image_path}\"\n"
            one_image[:template] << "TYPE=\"#{image_type}\"\n"
            one_image[:template] << "PERSISTENT=\"NO\"\n"
            one_image[:template] << "VCENTER_IMPORTED=\"YES\"\n"
            one_image[:template] << "DEV_PREFIX=\"#{image_prefix}\"\n"
        else
            # Return the image XML if it already exists
            one_image[:one] = image
        end

        return one_image
    end

    def self.get_one_image_ds_by_ref_and_dc(ref, dc_ref, vcenter_uuid, pool = nil)
        if pool.nil?
            pool = VCenterDriver::VIHelper.one_pool(OpenNebula::DatastorePool, false)
            if pool.respond_to?(:message)
                raise "Could not get OpenNebula DatastorePool: #{pool.message}"
            end
        end

        element = pool.select do |e|
            e["TEMPLATE/TYPE"]                == "IMAGE_DS" &&
            e["TEMPLATE/VCENTER_DS_REF"]      == ref &&
            e["TEMPLATE/VCENTER_DC_REF"]      == dc_ref &&
            e["TEMPLATE/VCENTER_INSTANCE_ID"] == vcenter_uuid
        end.first rescue nil

        return element
    end

    #  Checks if a RbVmomi::VIM::VirtualDevice is a disk or an iso file
    def self.is_disk_or_iso?(device)
        is_disk  = !(device.class.ancestors.index(RbVmomi::VIM::VirtualDisk)).nil?
        is_iso = device.backing.is_a? RbVmomi::VIM::VirtualCdromIsoBackingInfo
        is_disk || is_iso
    end


    def monitor
        summary = self['summary']

        total_mb = (summary.capacity.to_i / 1024) / 1024
        free_mb  = (summary.freeSpace.to_i / 1024) / 1024
        used_mb  = total_mb - free_mb

        "USED_MB=#{used_mb}\nFREE_MB=#{free_mb} \nTOTAL_MB=#{total_mb}"
    end

    def self.exists_one_by_ref_dc_and_type?(ref, dc_ref, vcenter_uuid, type, pool = nil)
        if pool.nil?
            pool = VCenterDriver::VIHelper.one_pool(OpenNebula::DatastorePool, false)
            if pool.respond_to?(:message)
                raise "Could not get OpenNebula DatastorePool: #{pool.message}"
            end
        end
        elements = pool.select do |e|
            e["TEMPLATE/TYPE"] == type &&
            e["TEMPLATE/VCENTER_DS_REF"] == ref &&
            e["TEMPLATE/VCENTER_DC_REF"] == dc_ref &&
            e["TEMPLATE/VCENTER_INSTANCE_ID"] == vcenter_uuid
        end

        return elements.size == 1
    end

    def to_one(ds_hash, vcenter_uuid, dc_name, dc_ref)
        one = ""
        one << "NAME=\"#{ds_hash[:name]}\"\n"
        one << "TM_MAD=vcenter\n"
        one << "VCENTER_INSTANCE_ID=\"#{vcenter_uuid}\"\n"
        one << "VCENTER_DC_REF=\"#{dc_ref}\"\n"
        one << "VCENTER_DC_NAME=\"#{dc_name}\"\n"
        one << "VCENTER_DS_NAME=\"#{ds_hash[:simple_name]}\"\n"
        one << "VCENTER_DS_REF=\"#{self['_ref']}\"\n"
        return one
    end

    def to_one_template(ds_hash, vcenter_uuid, dc_name, dc_ref, type)
        one_tmp = {
            :one  => to_one(ds_hash, vcenter_uuid, dc_name, dc_ref)
        }

        if type == "SYSTEM_DS"
            one_tmp[:one] << "TYPE=SYSTEM_DS\n"
        else
            one_tmp[:one] << "DS_MAD=vcenter\n"
            one_tmp[:one] << "TYPE=IMAGE_DS\n"
        end

        return one_tmp
    end

    def create_virtual_disk(img_name, size, adapter_type, disk_type)
        leading_dirs = img_name.split('/')[0..-2]
        if !leading_dirs.empty?
            create_directory(leading_dirs.join('/'))
        end

        ds_name = self['name']

        disk_type = 'preallocated' if disk_type == 'thick'

        vmdk_spec = RbVmomi::VIM::FileBackedVirtualDiskSpec(
            :adapterType => adapter_type,
            :capacityKb  => size.to_i*1024,
            :diskType    => disk_type
        )

        get_vdm.CreateVirtualDisk_Task(
          :datacenter => get_dc.item,
          :name       => "[#{ds_name}] #{img_name}.vmdk",
          :spec       => vmdk_spec
        ).wait_for_completion

        "#{img_name}.vmdk"
    end

    def create_directory(directory)
        ds_name = self['name']

        return if self.class == VCenterDriver::StoragePod

        directory_name = "[#{ds_name}] #{directory}"

        create_directory_params = {
            :name                     => directory_name,
            :datacenter               => get_dc.item,
            :createParentDirectories  => true
        }

        begin
            get_fm.MakeDirectory(create_directory_params)
        rescue RbVmomi::VIM::FileAlreadyExists => e
            # Do nothing if directory already exists
        end
    end

    def get_fm
        self['_connection.serviceContent.fileManager']
    end

    def get_vdm
        self['_connection.serviceContent.virtualDiskManager']
    end

    def get_dc
        item = @item

        while !item.instance_of? RbVmomi::VIM::Datacenter
            item = item.parent
            if item.nil?
                raise "Could not find the parent Datacenter"
            end
        end

        Datacenter.new(item)
    end



end # class Storage

class StoragePod < Storage

    def initialize(item, vi_client=nil)
        if !item.instance_of? RbVmomi::VIM::StoragePod
            raise "Expecting type 'RbVmomi::VIM::StoragePod'. " <<
                  "Got '#{item.class} instead."
        end

        @item = item
    end

     # This is never cached
    def self.new_from_ref(ref, vi_client)
        self.new(RbVmomi::VIM::StoragePod.new(vi_client.vim, ref), vi_client)
    end
end # class StoragePod

class Datastore < Storage

    attr_accessor :one_item

    def initialize(item, vi_client=nil)
        if !item.instance_of? RbVmomi::VIM::Datastore
            raise "Expecting type 'RbVmomi::VIM::Datastore'. " <<
                  "Got '#{item.class} instead."
        end

        @item = item
        @one_item = {}
    end

    def delete_virtual_disk(img_name)
        ds_name = self['name']

        begin
            get_vdm.DeleteVirtualDisk_Task(
            :name => "[#{ds_name}] #{img_name}",
            :datacenter => get_dc.item
            ).wait_for_completion
        rescue Exception => e
            # Ignore if file not found
            if !e.message.start_with?('ManagedObjectNotFound') &&
               !e.message.start_with?('FileNotFound')
                raise e
            end
        end
    end

    def delete_file(img_name)

        ds_name = self['name']

        begin
            get_fm.DeleteDatastoreFile_Task(
            :name => "[#{ds_name}] #{img_name}",
            :datacenter => get_dc.item
            ).wait_for_completion
        rescue Exception => e
            # Ignore if file not found
            if !e.message.start_with?('ManagedObjectNotFound') &&
               !e.message.start_with?('FileNotFound')
                raise e
            end
        end
    end

    # Copy a VirtualDisk
    def copy_virtual_disk(src_path, target_ds, target_path, new_size=nil)
        source_ds_name = self['name']
        target_ds_name = target_ds['name']

        leading_dirs = target_path.split('/')[0..-2]
        if !leading_dirs.empty?
            if source_ds_name == target_ds_name
                create_directory(leading_dirs.join('/'))
            else
                target_ds.create_directory(leading_dirs.join('/'))
            end
        end

        copy_params = {
            :sourceName       => "[#{source_ds_name}] #{src_path}",
            :sourceDatacenter => get_dc.item,
            :destName         => "[#{target_ds_name}] #{target_path}"
        }

        get_vdm.CopyVirtualDisk_Task(copy_params).wait_for_completion

        if new_size
            resize_spec = {
                :name => "[#{target_ds_name}] #{target_path}",
                :datacenter => target_ds.get_dc.item,
                :newCapacityKb => new_size,
                :eagerZero => false
            }

            get_vdm.ExtendVirtualDisk_Task(resize_spec).wait_for_completion
        end

        target_path
    end

    def rm_directory(directory)
        ds_name = self['name']

        rm_directory_params = {
            :name                     => "[#{ds_name}] #{directory}",
            :datacenter               => get_dc.item
        }

        get_fm.DeleteDatastoreFile_Task(rm_directory_params).wait_for_completion
    end

    def dir_empty?(path)
        ds_name = self['name']

        spec = RbVmomi::VIM::HostDatastoreBrowserSearchSpec.new

        search_params = {
            'datastorePath' => "[#{ds_name}] #{path}",
            'searchSpec'    => spec
        }

        begin
            search_task = self['browser'].SearchDatastoreSubFolders_Task(search_params)
            search_task.wait_for_completion
            empty = !!search_task.info.result &&
                    search_task.info.result.length == 1 &&
                    search_task.info.result.first.file.length == 0
        rescue
            empty = false
        end
    end


    def upload_file(source_path, target_path)
        @item.upload(target_path, source_path)
    end

    def download_file(source, target)
        @item.download(url_prefix + file, temp_folder + file)
    end

    # Get file size for image handling
    def stat(img_str)
        ds_name = self['name']
        img_path = File.dirname img_str
        img_name = File.basename img_str

        # Create Search Spec
        search_params = get_search_params(ds_name, img_path, img_name)

        # Perform search task and return results
        begin
            search_task = self['browser'].
                SearchDatastoreSubFolders_Task(search_params)

            search_task.wait_for_completion

            size = 0

            # Try to get vmdk capacity as seen by VM
            size = search_task.info.result[0].file[0].capacityKb / 1024 rescue nil

            # Try to get file size
            size = search_task.info.result[0].file[0].fileSize / 1024 / 1024 rescue nil if !size

            raise "Could not get file size or capacity" if size.nil?

            size
        rescue
            raise "Could not find file."
        end
    end

    def get_search_params(ds_name, img_path=nil, img_name=nil)
        spec         = RbVmomi::VIM::HostDatastoreBrowserSearchSpec.new

        vmdisk_query = RbVmomi::VIM::VmDiskFileQuery.new
        vmdisk_query.details = RbVmomi::VIM::VmDiskFileQueryFlags(:diskType        => true,
                                                                  :capacityKb      => true,
                                                                  :hardwareVersion => true,
                                                                  :controllerType  => true)

        spec.query   = [vmdisk_query,
                        RbVmomi::VIM::IsoImageFileQuery.new]
        spec.details = RbVmomi::VIM::FileQueryFlags(:fileOwner    => true,
                                                    :fileSize     => true,
                                                    :fileType     => true,
                                                    :modification => true)


        spec.matchPattern = img_name.nil? ? [] : [img_name]

        datastore_path = "[#{ds_name}]"
        datastore_path << " #{img_path}" if !img_path.nil?

        search_params = {'datastorePath' => datastore_path,
                         'searchSpec'    => spec}

        return search_params
    end

    def get_dc_path
        dc = get_dc
        p = dc.item.parent
        path = [dc.item.name]
        while p.instance_of? RbVmomi::VIM::Folder
            path.unshift(p.name)
            p = p.parent
        end
        path.delete_at(0) # The first folder is the root "Datacenters"
        path.join('/')
    end

    def generate_file_url(path)
        protocol = self[_connection.http.use_ssl?] ? 'https://' : 'http://'
        hostname = self[_connection.http.address]
        port     = self[_connection.http.port]
        dcpath   = get_dc_path

        # This creates the vcenter file URL for uploading or downloading files
        # e.g:
        url = "#{protocol}#{hostname}:#{port}/folder/#{path}?dcPath=#{dcpath}&dsName=#{self[name]}"
        return url
    end

    def download_to_stdout(remote_path)
        url = generate_file_url(remote_path)
        pid = spawn(CURLBIN,
                    "-k", '--noproxy', '*', '-f',
                    "-b", self[_connection.cookie],
                    url)

        Process.waitpid(pid, 0)
        fail "download failed" unless $?.success?
    end

    def is_descriptor?(remote_path)
        url = generate_file_url(remote_path)

        rout, wout = IO.pipe
        pid = spawn(CURLBIN,
                    "-I", "-k", '--noproxy', '*', '-f',
                    "-b", _connection.cookie,
                    url,
                    :out => wout,
                    :err => '/dev/null')

        Process.waitpid(pid, 0)
        fail "read image header failed" unless $?.success?

        wout.close
        size = rout.readlines.select{|l|
            l.start_with?("Content-Length")
        }[0].sub("Content-Length: ","")
        rout.close
        size.chomp.to_i < 4096   # If <4k, then is a descriptor
    end

    def get_text_file remote_path
        url = generate_file_url(remote_path)

        rout, wout = IO.pipe
        pid = spawn CURLBIN, "-k", '--noproxy', '*', '-f',
                    "-b", _connection.cookie,
                    url,
                    :out => wout,
                    :err => '/dev/null'

        Process.waitpid(pid, 0)
        fail "get text file failed" unless $?.success?

        wout.close
        output = rout.readlines
        rout.close
        return output
    end

    def get_images
        img_templates = []
        ds_id = nil
        ds_name = self['name']

        # We need OpenNebula Images and Datastores pools
        ipool = VCenterDriver::VIHelper.one_pool(OpenNebula::ImagePool, false)
        if ipool.respond_to?(:message)
            raise "Could not get OpenNebula ImagePool: #{pool.message}"
        end

        dpool = VCenterDriver::VIHelper.one_pool(OpenNebula::DatastorePool, false)
        if dpool.respond_to?(:message)
            raise "Could not get OpenNebula DatastorePool: #{pool.message}"
        end

        ds_id = @one_item["ID"]

        begin
            # Prepare sha256 crypto generator
            sha256        = Digest::SHA256.new

            # Create Search Spec
            search_params = get_search_params(ds_name)

            # Perform search task and return results
            search_task = self['browser'].SearchDatastoreSubFolders_Task(search_params)
            search_task.wait_for_completion

            # Loop through search results
            search_task.info.result.each do |result|

                # Remove [datastore] from file path
                folderpath = ""
                if result.folderPath[-1] != "]"
                    folderpath = result.folderPath.sub(/^\[#{ds_name}\] /, "")
                end

                # Loop through images in result.file
                result.file.each do |image|

                    image_path = ""

                    # Skip not relevant files
                    next if !["FloppyImageFileInfo",
                              "IsoImageFileInfo",
                              "VmDiskFileInfo"].include? image.class.to_s

                    # Get image path and name
                    image_path << folderpath << image.path
                    image_name = File.basename(image.path).reverse.sub("kdmv.","").reverse

                    # Get image's type
                    image_type  = image.class.to_s == "VmDiskFileInfo" ? "OS" : "CDROM"

                    # Get image's size
                    image_size  = image.capacityKb / 1024 rescue nil
                    image_size  = image.fileSize / 1024 / 1024 rescue nil if !image_size

                    # Assign image prefix if known or assign default prefix
                    controller = image.controllerType rescue nil
                    if controller
                        disk_prefix = controller == "VirtualIDEController" ? "hd" : "sd"
                    else
                        # Get default value for disks that are not attached to any controller
                        disk_prefix = VCenterDriver::VIHelper.get_default("IMAGE/TEMPLATE/DEV_PREFIX")
                    end

                    # Generate a crypto hash and get the first 12 characters
                    # this hash is used to avoid name collisions
                    full_name       = "#{image_name} - #{ds_name} [#{image_path}]"
                    image_hash      = sha256.hexdigest(full_name)[0..11]
                    import_name     = "#{image_name} - #{ds_name} [#{image_hash}]"

                    # Set template
                    one_image =  "NAME=\"#{import_name}\"\n"
                    one_image << "PATH=\"vcenter://#{image_path}\"\n"
                    one_image << "PERSISTENT=\"NO\"\n"
                    one_image << "TYPE=\"#{image_type}\"\n"
                    one_image << "VCENTER_IMPORTED=\"YES\"\n"
                    one_image << "DEV_PREFIX=\"#{disk_prefix}\"\n"

                    # Check image hasn't already been imported
                    vcenter_path = "vcenter://#{image_path}"
                    image_found = VCenterDriver::VIHelper.find_image_by_path(OpenNebula::ImagePool,
                                                                             vcenter_path,
                                                                             ds_id,
                                                                             ipool)

                    if !image_found
                        # Add template to image array
                        img_templates << {
                            :name        => import_name,
                            :path        => image_path,
                            :size        => image_size.to_s,
                            :type        => image.class.to_s,
                            :dsid        => ds_id,
                            :one         => one_image
                        }
                    end
                end
            end

        rescue Exception => e
            raise "Could not find images. Reason: #{e.message}/#{e.backtrace}"
        end

        return img_templates
    end

    # This is never cached
    def self.new_from_ref(ref, vi_client)
        self.new(RbVmomi::VIM::Datastore.new(vi_client.vim, ref), vi_client)
    end
end # class Datastore

end # module VCenterDriver

