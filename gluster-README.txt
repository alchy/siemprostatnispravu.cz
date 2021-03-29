gluster
-------

rpm --import key.centos_8.key
rpm --import key_centos_sig.key

rpm -ivh glusterfs-libs-7.8-1.el7.x86_64.rpm
rpm -ivh glusterfs-7.8-1.el7.x86_64.rpm
rpm -ivh glusterfs-client-xlators-7.8-1.el7.x86_64.rpm
rpm -ivh glusterfs-api-7.8-1.el7.x86_64.rpm
rpm -ivh glusterfs-cli-7.8-1.el7.x86_64.rpm
rpm -ivh glusterfs-fuse-7.8-1.el7.x86_64.rpm
rpm -ivh userspace-rcu-0.10.1-2.el8.x86_64.rpm
rpm -ivh glusterfs-server-7.8-1.el7.x86_64.rpm

systemctl start glusterd
systemctl enable glusterd
systemctl status glusterd

gluster peer probe FQND_d22

gluster volume create elk replica 6 FQDN12:/data/elk FQDND22:/data/elk FQDN13:/data/elk FQDN23:/data/elk FQDN14:/data/elk FQDN24:/data/elk

gluster volume start elk

gluster volume info

mount -t glusterfs localhost:/gv0 /mnt/elastic/

localhost:/elk /mnt/elk/ glusterfs  defaults,_netdev 0 0
mkdir -p /mnt/elk/etc/logstash/conf.d/
ln -s /mnt/elk/etc/logstash/conf.d/ /etc/logstash/conf.d

systemctl edit logstash.service
[Service]
Environment="HOSTNAME=FQDN14"

cat /etc/systemd/system/logstash.service.d/override.conf

vim /etc/systemd/system/logstash.service
ExecStart=/usr/share/logstash/bin/logstash "--path.settings" "/etc/logstash" "--config.reload.automatic"

# on systemd units
https://linuxconfig.org/how-to-create-systemd-service-unit-in-linux#h4-the-unit-section
