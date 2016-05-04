#!/bin/bash
############################################################
##########      Harden Ubuntu Server 15.10       ###########
############################################################
##                                                        ##
##                                                        ##
##                                                        ##
##                                                        ##
##                                                        ##
##                /\      /\                              ##
##              <~  ~>  <~  ~>                            ##
##               |/\|    |/\|                             ##
##                /\      /\                              ##
##                                                        ##
##               #  \    /`-\                             ##
##              / ###\  /`--_\                            ##
##            ,#     ##.`---__`.                          ##
##           /  ####    \--__ ~ \                         ##
##           #      #####__  ~~~~|                        ##
##           \#####     /  ~~~~~/                         ##
##            `____#####_~~---_'                          ##
############################################################
############################################################
############################################################

sudo apt-get install build-essential git libgpgme11-dev curl libgpg-error-dev libassuan-dev rkhunter chkrootkit logwatch ntp ntpdate apparmor apparmor-profiles fail2ban -y;

  echo "#
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 0

# Block SYN attacks
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv6.icmp_echo_ignore_broadcasts = 0

# Avoid a smurf attack
net.ipv4.icmp_echo_ignore_broadcasts = 0

# Turn on syncookies for SYN flood attack protection
net.ipv4.tcp_syncookies = 1

# Turn on and log spoofed, source routed, and redirect packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Turn on reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Make sure no one can alter the routing tables
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Don't act as a router
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Turn on execshild
kernel.exec-shield = 1
kernel.randomize_va_space = 1

# Tuen IPv6
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1

# Optimization for port usefor LBs
# Increase system file descriptor limit
fs.file-max = 65535

# Allow for more PIDs (to reduce rollover problems); may break some programs 32768
kernel.pid_max = 65536

# Increase system IP port limits
net.ipv4.ip_local_port_range = 2000 65000

# Increase TCP max buffer size setable using setsockopt()
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 87380 8388608

# Increase Linux auto tuning TCP buffer limits
# min, default, and max number of bytes to use
# set max to at least 4MB, or higher if you use very high BDP paths
# Tcp Windows etc
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
" >> /etc/sysctl.d/10-network-security.conf;
service procps start;

echo "order bind, hosts
nospoof on" >>/etc/host.conf ;

echo "GRUB_DISABLE_RECOVERY=\"true\"" >> /etc/default/grub;
sudo update-grub;
echo "tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab;

knock_port=$(awk 'BEGIN{srand();print int(rand()*(63000-2000))+2000 }');
iptables -F;
iptables -X;
iptables -A FORWARD -i eth1 -j DROP;
iptables -A INPUT -i eth1 -j DROP;
iptables -P INPUT ACCEPT;
iptables -P FORWARD ACCEPT;
iptables -P OUTPUT ACCEPT;
iptables -A INPUT -i lo -j ACCEPT;
iptables -A INPUT -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp -s 10.0.10.100 --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j DROP
iptables -A INPUT -p tcp -m tcp --dport 21457 -m recent --set --name KNOCKING --rsource
iptables -A INPUT -p tcp -m tcp --dport 15000 -m recent --rcheck --seconds 15 --name KNOCKING --rsource -m limit --limit 10/minute --limit-burst 20 -j ACCEPT
iptables -A INPUT -j REJECT --reject-with icmp-port-unreachable
iptables -A INPUT -j DROP
apt-get install iptables-save -y;
iptables-save;

#setup fail2ban
echo "[ssh]
enabled  = true
port     = $ssh_port
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5" >>/etc/fail2ban/jail.conf
