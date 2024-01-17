# -*- mode: ruby -*-
# vi: set ft=ruby :


Vagrant.configure("2") do |config|



  config.vm.define "wolServer" do |wolServer|
    wolServer.vm.box = "wolServer"
    wolServer.vm.hostname = "wolServer"

    wolServer.vm.box = "generic/debian12"

    wolServer.vm.network "private_network", type: "dhcp"

    wolServer.vm.synced_folder ".", "/opt/wolRelay.vagrant"

    wolServer.vm.synced_folder ".", "/vagrant", disabled: false

    wolServer.vm.provider "virtualbox" do |vb|
      #vb.gui = true
    end

    wolServer.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y python3.11-venv python3-dev libpcap0.8
    SHELL

  end

  config.vm.define "wolClient" do |wolClient|
    wolClient.vm.box = "wolClient"
    wolClient.vm.hostname = "wolClient"

    wolClient.vm.box = "generic/debian12"

    wolClient.vm.network "private_network", type: "dhcp"

    wolClient.vm.synced_folder ".", "/vagrant", disabled: false

    wolClient.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y wakeonlan
    SHELL
  end

  
end
