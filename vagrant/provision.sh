#!/bin/bash

## Settin non-interactive mode
export DEBIAN_FRONTEND=noninteractive

## Locale settings (Ubuntu cloud image has an incomplete locale configuration)
sudo sh -c "echo 'LC_ALL=en_US.UTF-8\nLANG=en_US.UTF-8' > /etc/default/locale"
sudo apt-get update
sudo apt-get -y install language-pack-en

## Install tools
sudo apt-get -y install htop
sudo apt-get -y install git

## Install mysql server
sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password password toor'
sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password toor'
sudo apt-get -y install mysql-server

## Install phpmyadmin
sudo debconf-set-selections <<< 'phpmyadmin phpmyadmin/dbconfig-install boolean true'
sudo debconf-set-selections <<< 'phpmyadmin phpmyadmin/app-password-confirm password toor'
sudo debconf-set-selections <<< 'phpmyadmin phpmyadmin/mysql/admin-pass password toor'
sudo debconf-set-selections <<< 'phpmyadmin phpmyadmin/mysql/app-pass password toor'
sudo debconf-set-selections <<< 'phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2'
sudo apt-get -y install phpmyadmin
# phpmyadmin wants mcrypt, which is not enabled by default (http://php.net/manual/en/mcrypt.installation.php)
sudo php5enmod mcrypt
sudo service apache2 restart

## Install python/django
sudo apt-get -y install python-mysqldb
sudo apt-get -y install python-pip
sudo pip install django
sudo pip install tabulate
sudo pip install django-extra-views
sudo pip install pycrypto
sudo pip install django-pure-pagination

## Install Distorm
sudo apt-get -y install gcc
sudo apt-get -y install unzip
unzip /vagrant/vagrant/distorm3.zip -d /home/vagrant/build
python /home/vagrant/build/distorm3/setup.py build
sudo python /home/vagrant/build/distorm3/setup.py install

## Create Ramdisk
sudo sh -c 'echo "tmpfs /media/tmpfs tmpfs defaults,size=3072M 0 0" >> /etc/fstab'
sudo mkdir -p /media/tmpfs
sudo mount -a

sudo mkdir -p /media/tmpfs/malfind_dumps
sudo chown vagrant:vagrant /media/tmpfs/malfind_dumps

## Vortessence directories
mkdir -p /vagrant/data/upload
mkdir -p /vagrant/data/target

## Initialize DB
mysql -u root --password=toor < /vagrant/vagrant/create_db_user.sql
python /vagrant/vortessence/manage.py makemigrations
python /vagrant/vortessence/manage.py migrate
python /vagrant/vortessence/manage.py makemigrations vortessence
python /vagrant/vortessence/manage.py migrate vortessence
mysql -u root --password=toor < /vagrant/vagrant/insert_db_profiles.sql

## Link scripts to path
sudo ln -s /vagrant/vagrant/scripts/vort_web_init.sh /usr/local/bin/
sudo ln -s /vagrant/vagrant/scripts/vort_web_run.sh /usr/local/bin/

## Link vort.py to path
sudo ln -s /vagrant/vortessence/vort.py /usr/local/bin/

