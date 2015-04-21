# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  # Build off Ubuntu 14.04 64bit image
  config.vm.box = "ubuntu/trusty64"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Port forwarding
  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.

  # vortessence_web
  config.vm.network "forwarded_port", guest: 8000, host: 8000, host_ip: "127.0.0.1", auto_correct: true
  # phpmyadmin
  config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1", auto_correct: true

  # Hostname
  config.vm.hostname = "vortessence"

  # If true, then any SSH connections made will enable agent forwarding.
  # Default value: false
  # config.ssh.forward_agent = true

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Shell provisioning
  config.vm.provision "shell", path: "vagrant/provision.sh"
  config.vm.post_up_message = "VORTESSENCE VM\n==============\n\nQuickstart:\n-----------\nSSH to guest:\n$ vagrant ssh\n\nExecute Vortessence CLI:\nvagrant@vortessence:~$ cd /vagrant/vortessence\nvagrant@vortessence:~$ python vort.py -h\n\nInitialize frontend admin:\nvagrant@vortessence:~$ vort_web_init.sh\n\nRun frontend:\nvagrant@vortessence:~$ vort_web_run.sh\n\n\nWeb access from host:\n---------------------\n\nVortessence Frontend:\nhttp://localhost:8000/\n\nphpMyAdmin (credentials: root/toor):\nhttp://localhost:8080/phpmyadmin/\n\nHint: Project root (git repo) is mounted under /vagrant"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.

  # Virtualbox
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 4096
    vb.cpus = 4

    ## Uncomment to disable headless mode
    #vb.gui = true
  end

end
