#!/bin/bash

function countdown() {
  local i
  sleep 1
  for ((i=$1-1; i>=1; i--)); do
    printf '\b\b%02d' "$i"
    sleep 1
  done
}

function fail() {
  echo "ERROR: Fuel node deployment FAILED! Check /var/log/puppet/bootstrap_admin_node.log for details" 1>&2
  exit 1
}
# LANG variable is a workaround for puppet-3.4.2 bug. See LP#1312758 for details
export LANG=en_US.UTF8
showmenu="no"
if [ -f /root/.showfuelmenu ]; then
  . /root/.showfuelmenu
fi

echo -n "Applying default Fuel settings..."
fuelmenu --save-only --iface=eth0
echo "Done!"

if [[ "$showmenu" == "yes" || "$showmenu" == "YES" ]]; then
  fuelmenu
  else
  #Give user 15 seconds to enter fuelmenu or else continue
  echo
  echo -n "Press a key to enter Fuel Setup (or press ESC to skip)... 15"
  countdown 15 & pid=$!
  if ! read -s -n 1 -t 15 key; then
    echo -e "\nSkipping Fuel Setup..."
  else
    { kill "$pid"; wait $!; } 2>/dev/null
    case "$key" in
      $'\e')  echo "Skipping Fuel Setup.."
              echo -n "Applying default Fuel setings..."
              fuelmenu --save-only --iface=eth0
              echo "Done!"
              ;;
      *)      echo -e "\nEntering Fuel Setup..."
              fuelmenu
              ;;
    esac
  fi
fi
#Reread /etc/sysconfig/network to inform puppet of changes
. /etc/sysconfig/network
hostname "$HOSTNAME"

### docker stuff
images_dir="/var/www/nailgun/docker/images"

# extract docker images
mkdir -p $images_dir $sources_dir
rm -f $images_dir/*tar
pushd $images_dir &>/dev/null

echo "Extracting and loading docker images. (This may take a while)"
lrzip -d -o fuel-images.tar fuel-images.tar.lrz && tar -xf fuel-images.tar && rm -f fuel-images.tar
popd &>/dev/null
service docker start

# load docker images
for image in $images_dir/*tar ; do
    echo "Loading docker image ${image}..."
    docker load -i "$image"
    # clean up extracted image
    rm -f "$image"
done

# apply puppet
puppet apply --detailed-exitcodes -d -v /etc/puppet/modules/nailgun/examples/host-only.pp
if [ $? -ge 4 ];then
  fail
fi
rmdir /var/log/remote && ln -s /var/log/docker-logs/remote /var/log/remote

dockerctl check || fail
bash /etc/rc.local
echo "Fuel node deployment complete!"

cat << EOF > /root/patch.diff
diff -rupN /root/puppet_iso/modules/keystone/lib/puppet/provider/keystone_user/keystone.rb /etc/puppet/modules/keystone/lib/puppet/provider/keystone_user/keystone.rb
--- /root/puppet_iso/modules/keystone/lib/puppet/provider/keystone_user/keystone.rb	2015-03-12 16:12:33.000000000 +0000
+++ /etc/puppet/modules/keystone/lib/puppet/provider/keystone_user/keystone.rb	2015-03-12 18:04:27.219843101 +0000
@@ -25,7 +25,7 @@ Puppet::Type.type(:keystone_user).provid
   end

   def self.user_hash
-    @user_hash = build_user_hash
+    @user_hash ||= build_user_hash
   end

   def user_hash
@@ -81,48 +81,26 @@ Puppet::Type.type(:keystone_user).provid
   end

   def password
-    # if we don't know a password we can't test it
-    return nil if resource[:password] == nil
-    # we can't get the value of the password but we can test to see if the one we know
-    # about works, if it doesn't then return nil, causing it to be reset
-    begin
-      token_out = creds_keystone(resource[:name], resource[:tenant], resource[:password], "token-get")
-    rescue Exception => e
-      return nil if e.message =~ /Not Authorized/ or e.message =~ /HTTP 401/
-      raise e
-    end
-    return resource[:password]
+#    Puppet.warning("Cannot retrieve password")
+    user_hash[resource[:name]][:password]
   end

   def password=(value)
-    if resource[:manage_password] == 'True'
-      auth_keystone('user-password-update', '--pass', value, user_hash[resource[:name]][:id])
-    end
+#    Puppet.warning('Cannot update password')
+#    # user-password-update does not support the ability know what the
+#    # current value is
+#    #auth_keystone(
+#    #  'user-password-update',
+#    #  '--pass', value,
+#    #  user_hash[resource[:name]][:id]
   end

   def tenant
-    return resource[:tenant] if resource[:ignore_default_tenant]
-    user_id = user_hash[resource[:name]][:id]
-    begin
-      tenantId = self.class.get_keystone_object('user', user_id, 'tenantId')
-    rescue
-      tenantId = nil
-    end
-    if tenantId.nil? or tenantId == 'None' or tenantId.empty?
-      tenant = 'None'
-    else
-      # this prevents is from failing if tenant no longer exists
-      begin
-        tenant = self.class.get_keystone_object('tenant', tenantId, 'name')
-      rescue
-        tenant = 'None'
-      end
-    end
-    tenant
+    user_hash[resource[:name]][:tenant]
   end

   def tenant=(value)
-    fail("tenant cannot be updated. Transition requested: #{user_hash[resource[:name]][:tenant]} -> #{value}")
+#    fail("tenant cannot be updated. Transition requested: #{user_hash[resource[:name]][:tenant]} -> #{value}")
   end

   def email
@@ -137,36 +115,45 @@ Puppet::Type.type(:keystone_user).provid
     )
   end

-  def manage_password
-    user_hash[resource[:name]][:manage_password]
-  end
-
-  def manage_password=(value)
-    user_hash[resource[:name]][:manage_password]
-  end
-
   def id
     user_hash[resource[:name]][:id]
   end

   private

+    def self.get_tennat_for_user(userid)
+      res = nil
+      list_keystone_objects('tenant',3).each do |tenant|
+        list_keystone_objects('user',4,'--tenant',tenant[0]).each do |user|
+          if userid == user[0]
+            res = tenant[0]
+          end
+        end
+      end
+      res
+    end
+
     def self.build_user_hash
       hash = {}
       list_keystone_objects('user', 4).each do |user|
+        #tenantId = get_keystone_object('user', user[0], 'tenantId')
+        tenantId = self.get_tennat_for_user(user[0])
+        if tenantId.nil? or tenantId == 'None' or tenantId.empty?
+          tenant = 'None'
+        else
+          tenant = get_keystone_object('tenant', tenantId, 'name')
+        end
         password = 'nil'
-        manage_password = 'True',
         hash[user[1]] = {
-          :id              => user[0],
-          :enabled         => user[2],
-          :email           => user[3],
-          :name            => user[1],
-          :password        => password,
-          :manage_password => manage_password,
+          :id          => user[0],
+          :enabled     => user[2],
+          :email       => user[3],
+          :name        => user[1],
+          :password    => password,
+          :tenant      => tenant
         }
       end
       hash
     end

 end
-
diff -rupN /root/puppet_iso/modules/keystone/lib/puppet/provider/keystone_user_role/keystone.rb /etc/puppet/modules/keystone/lib/puppet/provider/keystone_user_role/keystone.rb
--- /root/puppet_iso/modules/keystone/lib/puppet/provider/keystone_user_role/keystone.rb	2015-03-12 16:12:33.000000000 +0000
+++ /etc/puppet/modules/keystone/lib/puppet/provider/keystone_user_role/keystone.rb	2015-03-12 18:04:27.219843101 +0000
@@ -19,7 +19,7 @@ Puppet::Type.type(:keystone_user_role).p
   end

   def self.user_role_hash
-    @user_role_hash = build_user_role_hash
+    @user_role_hash ||= build_user_role_hash
   end

   def user_role_hash
@@ -33,69 +33,79 @@ Puppet::Type.type(:keystone_user_role).p
   end

   def create
-    user_id, tenant_id = get_user_and_tenant
+    #user_id, tenant_id = get_user_and_tenant
+    user_id, tenant_id = get_username_and_tenantid
     resource[:roles].each do |role_name|
-      role_id = self.class.get_role(role_name)
+      role_id = self.class.get_roles[role_name]
       auth_keystone(
         'user-role-add',
-        '--user-id', user_id,
+        #'--user-id', user_id,
+        '--user', user_id,
         '--tenant-id', tenant_id,
         '--role-id', role_id
       )
     end
   end

-  def self.get_user_and_tenant(user, tenant)
-    @tenant_hash ||= {}
-    @user_hash   ||= {}
-    @tenant_hash[tenant] = @tenant_hash[tenant] || get_tenant(tenant)
-    [
-      get_user(@tenant_hash[tenant], user),
-      @tenant_hash[tenant]
-    ]
+  def get_user_and_tenant
+    user, tenant = resource[:name].split('@', 2)
+    tenant_id = self.class.get_tenants[tenant]
+    #notice(">>>")
+    #notice(tenant_id)
+    #notice(self.class.get_users(tenant_id))
+    [self.class.get_users(tenant_id)[user], self.class.get_tenants[tenant]]
   end

-  def get_user_and_tenant
+  def get_username_and_tenantid
     user, tenant = resource[:name].split('@', 2)
-    self.class.get_user_and_tenant(user, tenant)
+    tenant_id = self.class.get_tenants[tenant]
+    #notice(">>>")
+    #notice(tenant_id)
+    #notice(self.class.get_users(tenant_id))
+    [user, self.class.get_tenants[tenant]]
   end

   def exists?
-    user_id, tenant_id = get_user_and_tenant
-    get_user_tenant_hash(user_id, tenant_id)
+    user_role_hash[resource[:name]]
   end

   def destroy
-    user_id, tenant_id = get_user_and_tenant
-    get_user_tenant_hash(user_id, tenant_id)[:role_ids].each do |role_id|
-      auth_keystone(
-       'user-role-remove',
-       '--user-id', user_id,
-       '--tenant-id', tenant_id,
-       '--role-id', role_id
-      )
+    user_role_hash[resource[:name]][:role_ids].each do |role_id|
+      begin
+        auth_keystone(
+          'user-role-remove',
+          '--user-id', user_role_hash[resource[:name]][:user_id],
+          '--tenant-id', user_role_hash[resource[:name]][:tenant_id],
+          '--role-id', role_id
+        )
+      rescue Exception => e
+        if e.message =~ /(\(HTTP\s+404\))/
+          notice("Role has been already deleted. Nothing to do")
+        else
+          raise(e)
+        end
+      end
     end
   end

   def id
-    user_id, tenant_id = get_user_and_tenant
-    get_user_tenant_hash(user_id, tenant_id)[:id]
+    user_role_hash[resource[:name]][:id]
   end

   def roles
-    user_id, tenant_id = get_user_and_tenant
-    get_user_tenant_hash(user_id, tenant_id)[:role_names]
+    user_role_hash[resource[:name]][:role_names]
   end

   def roles=(value)
     # determine the roles to be added and removed
+    # require 'ruby-debug';debugger
     remove = roles - Array(value)
     add    = Array(value) - roles

     user_id, tenant_id = get_user_and_tenant

     add.each do |role_name|
-      role_id = self.class.get_role(role_name)
+      role_id = self.class.get_roles[role_name]
       auth_keystone(
         'user-role-add',
         '--user-id', user_id,
@@ -104,15 +114,22 @@ Puppet::Type.type(:keystone_user_role).p
       )
     end
     remove.each do |role_name|
-      role_id = self.class.get_role(role_name)
-      auth_keystone(
-        'user-role-remove',
-        '--user-id', user_id,
-        '--tenant-id', tenant_id,
-        '--role-id', role_id
-      )
+      role_id = self.class.get_roles[role_name]
+      begin
+          auth_keystone(
+              'user-role-remove',
+              '--user-id', user_id,
+              '--tenant-id', tenant_id,
+              '--role-id', role_id
+          )
+      rescue Exception => e
+        if e.message =~ /(\(HTTP\s+404\))/
+            notice("Role has been already deleted. Nothing to do")
+        else
+          raise(e)
+        end
+      end
     end
-
   end

   private
@@ -121,7 +138,7 @@ Puppet::Type.type(:keystone_user_role).p
       hash = {}
       get_tenants.each do |tenant_name, tenant_id|
         get_users(tenant_id).each do |user_name, user_id|
-          list_user_roles(user_id, tenant_id).sort.each do |role|
+          list_user_roles(user_id, tenant_id).each do |role|
             hash["#{user_name}@#{tenant_name}"] ||= {
               :user_id    => user_id,
               :tenant_id  => tenant_id,
@@ -133,34 +150,21 @@ Puppet::Type.type(:keystone_user_role).p
           end
         end
       end
+#require 'ruby-debug';debugger
       hash
     end

-    # lookup the roles for a single tenant/user combination
-    def get_user_tenant_hash(user_id, tenant_id)
-      @user_tenant_hash ||= {}
-      unless @user_tenant_hash["#{user_id}@#{tenant_id}"]
-        list_user_roles(user_id, tenant_id).sort.each do |role|
-          @user_tenant_hash["#{user_id}@#{tenant_id}"] ||= {
-            :user_id    => user_id,
-            :tenant_id  => tenant_id,
-            :role_names => [],
-            :role_ids   => []
-          }
-          @user_tenant_hash["#{user_id}@#{tenant_id}"][:role_names].push(role[1])
-          @user_tenant_hash["#{user_id}@#{tenant_id}"][:role_ids].push(role[0])
-        end
-      end
-      @user_tenant_hash["#{user_id}@#{tenant_id}"]
-    end
-

     def self.list_user_roles(user_id, tenant_id)
       # this assumes that all returned objects are of the form
       # id, name, enabled_state, OTHER
       number_columns = 4
       role_output = auth_keystone('user-role-list', '--user-id', user_id, '--tenant-id', tenant_id)
-      list = (role_output.split("\n")[3..-2] || []).collect do |line|
+      list = (role_output.split("\n")[3..-2] || []).select do
+          |line| line =~ /^\|.*\|$/
+      end.reject do
+              |line| line =~ /^\|\s+id\s+\|\s+name\s+\|\s+user_id\s+\|\s+tenant_id\s+\|$/
+      end.collect do |line|
         row = line.split(/\s*\|\s*/)[1..-1]
         if row.size != number_columns
           raise(Puppet::Error, "Expected #{number_columns} columns for #{type} row, found #{row.size}. Line #{line}")
@@ -170,23 +174,9 @@ Puppet::Type.type(:keystone_user_role).p
       list
     end

-    def list_user_roles(user_id, tenant_id)
-      self.class.list_user_roles(user_id, tenant_id)
-    end
-
-    def self.get_user(tenant_id, name)
-      @users ||= {}
-      user_key = "#{name}@#{tenant_id}"
-      unless @users[user_key]
-        list_keystone_objects('user', 4, '--tenant-id', tenant_id).each do |user|
-          @users["#{user[1]}@#{tenant_id}"] = user[0]
-        end
-      end
-      @users[user_key]
-    end
-
     def self.get_users(tenant_id='')
       @users = {}
+
       list_keystone_objects('user', 4, '--tenant-id', tenant_id).each do |user|
         @users[user[1]] = user[0]
       end
@@ -194,36 +184,19 @@ Puppet::Type.type(:keystone_user_role).p
     end

     def self.get_tenants
-      unless @tenants
-        @tenants = {}
-        list_keystone_objects('tenant', 3).each do |tenant|
-          @tenants[tenant[1]] = tenant[0]
-        end
+      @tenants = {}
+      list_keystone_objects('tenant', 3).each do |tenant|
+        @tenants[tenant[1]] = tenant[0]
       end
       @tenants
     end

-    def self.get_tenant(name)
-      unless (@tenants and @tenants[name])
-        @tenants = {}
-        list_keystone_objects('tenant', 3).each do |tenant|
-          if tenant[1] == name
-            @tenants[tenant[1]] = tenant[0]
-            #tenant
-          end
-        end
-      end
-      @tenants[name]
-    end
-
-    def self.get_role(name)
-      @roles ||= {}
-      unless @roles[name]
-        list_keystone_objects('role', 2).each do |role|
-          @roles[role[1]] = role[0]
-        end
+    def self.get_roles
+      @roles = {}
+      list_keystone_objects('role', 2).each do |role|
+        @roles[role[1]] = role[0]
       end
-      @roles[name]
+      @roles
     end

 end
diff -rupN /root/puppet_iso/modules/keystone/lib/puppet/type/keystone_user.rb /etc/puppet/modules/keystone/lib/puppet/type/keystone_user.rb
--- /root/puppet_iso/modules/keystone/lib/puppet/type/keystone_user.rb	2015-03-12 16:12:33.000000000 +0000
+++ /etc/puppet/modules/keystone/lib/puppet/type/keystone_user.rb	2015-03-12 18:04:27.220843101 +0000
@@ -16,11 +16,6 @@ Puppet::Type.newtype(:keystone_user) do
     newvalues(/\S+/)
   end

-  newparam(:ignore_default_tenant, :boolean => true) do
-    newvalues(:true, :false)
-    defaultto false
-  end
-
   newproperty(:enabled) do
     newvalues(/(t|T)rue/, /(f|F)alse/)
     defaultto('True')
@@ -29,23 +24,8 @@ Puppet::Type.newtype(:keystone_user) do
     end
   end

-  newproperty(:password) do
+  newparam(:password) do
     newvalues(/\S+/)
-    def change_to_s(currentvalue, newvalue)
-      if currentvalue == :absent
-        return "created password"
-      else
-        return "changed password"
-      end
-    end
-
-    def is_to_s( currentvalue )
-      return '[old password redacted]'
-    end
-
-    def should_to_s( newvalue )
-      return '[new password redacted]'
-    end
   end

   newproperty(:tenant) do
@@ -62,14 +42,6 @@ Puppet::Type.newtype(:keystone_user) do
     end
   end

-  newproperty(:manage_password) do
-    newvalues(/(t|T)rue/, /(f|F)alse/)
-    defaultto('True')
-    munge do |value|
-      value.to_s.capitalize
-    end
-  end
-
   autorequire(:keystone_tenant) do
     self[:tenant]
   end
EOF
echo $?

yum install -y patch
echo $?

patch -p4 -d /etc/puppet/modules < /root/patch.diff
echo $?

