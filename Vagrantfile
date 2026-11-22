# Test lab: one Rocky Linux 9 VM and one Ubuntu 24.04 VM (VirtualBox).
# Ansible runs inside each VM (ansible_local), so it also works from Windows.
#
#   vagrant up --provision-with audit_before     # create VMs + Lynis score "before"
#   vagrant provision --provision-with harden    # apply the role
#   vagrant provision --provision-with audit_after
#
# Reports are written to ./reports (shared with the VMs).

VMS = {
  "rocky9"   => { box: "bento/rockylinux-9", ip: "192.168.56.10" },
  "ubuntu24" => { box: "bento/ubuntu-24.04", ip: "192.168.56.11" },
}

Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/vagrant"

  VMS.each do |name, opts|
    config.vm.define name do |vm|
      vm.vm.box = opts[:box]
      vm.vm.hostname = name
      vm.vm.network "private_network", ip: opts[:ip]
      vm.vm.provider "virtualbox" do |vb|
        vb.memory = 1024
        vb.cpus = 1
      end

      common = lambda do |a|
        a.install_mode = "pip"
        a.config_file = "/vagrant/ansible.cfg"
        a.inventory_path = "/vagrant/inventory/vagrant-local.ini"
        a.limit = "localhost"
        a.provisioning_path = "/vagrant"
      end

      vm.vm.provision "audit_before", type: "ansible_local", run: "never" do |a|
        common.call(a)
        a.playbook = "playbooks/audit.yml"
        a.extra_vars = { audit_label: "before", report_prefix: name }
      end

      vm.vm.provision "harden", type: "ansible_local", run: "never" do |a|
        common.call(a)
        a.playbook = "playbooks/site.yml"
      end

      vm.vm.provision "audit_after", type: "ansible_local", run: "never" do |a|
        common.call(a)
        a.playbook = "playbooks/audit.yml"
        a.extra_vars = { audit_label: "after", report_prefix: name }
      end
    end
  end
end
