# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # config.vm.provider "virtualbox" do |v|
  #  v.cpus = 2
  #  v.memory = 2048
  #  v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
  #  v.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
  #end
  
  config.vm.define "centos7" do |d|
    d.vm.box = "bento/centos-7"
    d.vm.hostname = "centos7"
    d.vm.provision "shell", path: "bin/centos-bootstrap.sh", privileged: "true"
  end
  
end
