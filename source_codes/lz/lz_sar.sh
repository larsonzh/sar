#!/bin/sh
# lz_sar.sh v1.0.6
# By LZ 妙妙呜 (larsonzhang@gmail.com)

## 设置文件同步锁
[ ! -d /var/lock ] && { mkdir -p /var/lock; chmod 777 /var/lock; }
exec 555<>/var/lock/lz_rule.lock; flock -x 555 > /dev/null 2>&1;

## 1、本单臂路由脚本仅适于华硕官改及梅林固件hnd/axhnd/axhnd.675x平台路由器使用。
## 2、路由器通过WAN口直接接入上一级外部网络和运营商IPTV网络。
## 3、单线复用接入时，路由器WAN口可同时接入上一级外部网络、运营商IPTV网络的两个网络。
## 4、每个WAN口可以连接4条外部VLAN，通过TRUNK通道向外延伸路由器内部网络。
## 5、不要在脚本中设置路由器内已有且相同的VLAN ID，会导致设置无效。
## 6、不要与LZ IPTV脚本（lz_iptv.sh）同时运行和使用。
## 7、启动单臂路由服务命令：/jffs/scripts/lz/lz_sar.sh
## 8、停止单臂路由服务命令：/jffs/scripts/lz/lz_sar.sh stop
## 9、从路由器中清除此脚本前，请执行一次“停止单臂路由服务命令”以释放脚本曾经分配过的系统资源。

## ----------------------单臂路由用户参数设置区----------------------

## 第一WAN口1号本地内网子接口VLAN_ID值（1~4095；其他--未用）
wan1_1_vlan_id=

## 第一WAN口2号本地内网子接口VLAN_ID值（1~4095；其他--未用）
wan1_2_vlan_id=

## 第一WAN口3号本地内网子接口VLAN_ID值（1~4095；其他--未用）
wan1_3_vlan_id=

## 第一WAN口4号本地内网子接口VLAN_ID值（1~4095；其他--未用）
wan1_4_vlan_id=


## 第二WAN口1号本地内网子接口VLAN_ID值（1~4095；其他--未用）
wan2_1_vlan_id=

## 第二WAN口2号本地内网子接口VLAN_ID值（1~4095；其他--未用）
wan2_2_vlan_id=

## 第二WAN口3号本地内网子接口VLAN_ID值（1~4095；其他--未用）
wan2_3_vlan_id=

## 第二WAN口4号本地内网子接口VLAN_ID值（1~4095；其他--未用）
wan2_4_vlan_id=


## IPTV机顶盒接入WAN口（1--第一WAN口；2--第二WAN口；其他--禁用）
## 缺省为禁用。
iptv_stb_wan=5

## IPTV机顶盒获取IP地址方式（1--DHCP或IPoE；2--静态IP；3--PPPoE）
## 缺省为DHCP或IPoE。
iptv_stb_get_ip_mode=1

## IPTV机顶盒访问IPTV网络方式（1--直连IPTV网络；2--按服务地址访问）
## 缺省为直连IPTV线路。
iptv_stb_access_mode=1

## hnd平台机型核心网桥组播控制方式（0--禁用；1--标准方式；2--阻塞方式）
## 缺省为阻塞方式。
## 此参数仅对hnd/axhnd/axhnd.675x等hnd平台机型路由器有效，IPTV机顶盒
## 不能正常播放节目时可尝试调整此参数。
hnd_br0_bcmmcast_mode=2

## IPTV机顶盒内网IP地址列表（可逐行填入多个机顶盒地址）
cat > /tmp/lz_iptv_box_ip.lst <<EOF
## 在地址条目前加#注释符，可使该条目失效
10.0.0.46	# 机顶盒-1
#10.0.0.101	# 机顶盒-2

EOF

## IPTV网络服务IP网址/网段列表（可逐行填入多个地址条目）
## 仅在机顶盒访问IPTV网络方式为“按服务地址访问”时使用
cat > /tmp/lz_iptv_ip_addr.lst <<EOF
## 在地址条目前加#注释符，可使该条目失效

EOF

## --------------------------参数设置区结束--------------------------


## 版本号
LZ_VERSION=v1.0.6

## 项目文件部署路径
PATH_BASE=/jffs/scripts
PATH_LZ=${PATH_BASE}/lz

## 项目临时文件目录
PATH_TMP=${PATH_LZ}/tmp

## 项目标识及项目文件名
PROJECT_ID=lz_sar
PROJECT_FILENAME=${PROJECT_ID}.sh

## 自启动引导文件部署路径
PATH_BOOTLOADER=${PATH_BASE}

## 自启动引导文件名
BOOTLOADER_NAME=firewall-start

## 同步锁文件路径
PATH_LOCK=/var/lock

## 文件同步锁全路径文件名
LOCK_FILE=${PATH_LOCK}/lz_rule.lock

## 同步锁文件ID
LOCK_FILE_ID=555

## 第一WAN口路由表ID号
WAN0=100

## 第二WAN口路由表ID号
WAN1=200

## IPTV路由表ID
LZ_IPTV=888

## IPTV规则优先级
IP_RULE_PRIO_IPTV=888

## 策略规则基础优先级--25000（IP_RULE_PRIO）
IP_RULE_PRIO=25000


## 项目文件及目录管理
lz_optimize_file_directory_structure() {
	[ ! -d ${PATH_LZ} ] && { mkdir -p ${PATH_LZ}; }
	chmod 775 ${PATH_LZ}
	local current_filename="$0"
	if [ -n "$( echo "$current_filename" | grep "[\.][\/]" )" ]; then
		current_filename="$( pwd )""/""$( echo "$current_filename" | awk -F "[\.][\/]" '{print $2}' )"
	fi
	if [ ! -f ${PATH_LZ}/${PROJECT_FILENAME} ]; then
		cp -f $current_filename ${PATH_LZ} > /dev/null 2>&1
	elif [ "$current_filename" != ${PATH_LZ}/${PROJECT_FILENAME} ]; then
		if [ -n "$( cmp "$current_filename" ${PATH_LZ}/${PROJECT_FILENAME} )" ]; then
			cp -f $current_filename ${PATH_LZ} > /dev/null 2>&1
		fi
	fi
	chmod 775 ${PATH_LZ}/${PROJECT_FILENAME}
}

## 处理系统负载均衡分流策略规则函数
## 输入项：
##     $1--规则优先级（150--梅林原始；$IP_RULE_PRIO + 1--脚本定义）
##     全局常量
## 返回值：无
lz_sys_load_balance_control() {
	## a.对固件系统中第一WAN口的负载均衡分流策略采取主动控制措施
	local local_sys_load_balance_wan0_exist=$( ip rule show | grep -c "from all fwmark 0x80000000\/0xf0000000" )
	if [ $local_sys_load_balance_wan0_exist -gt 0 ]; then
		until [ $local_sys_load_balance_wan0_exist = 0 ]
		do
			ip rule show | grep "from all fwmark 0x80000000\/0xf0000000" | sed -e "s/^\(.*\)\:/ip rule del prio \1/g" | \
				awk '{system($0 " > \/dev\/null 2>\&1")}'
			local_sys_load_balance_wan0_exist=$( ip rule show | grep -c "from all fwmark 0x80000000\/0xf0000000" )
		done
		ip route flush cache > /dev/null 2>&1
		## 不清除系统负载均衡策略中的分流功能，但降低其执行优先级，防止先于自定义分流规则执行
		ip rule add from all fwmark 0x80000000/0xf0000000 table $WAN0 prio "$1" > /dev/null 2>&1
		ip route flush cache > /dev/null 2>&1
	fi

	## b.对固件系统中第二WAN口的负载均衡分流策略采取主动控制措施
	local local_sys_load_balance_wan1_exist=$( ip rule show | grep -c "from all fwmark 0x90000000\/0xf0000000" )
	if [ $local_sys_load_balance_wan1_exist -gt 0 ]; then
		until [ $local_sys_load_balance_wan1_exist = 0 ]
		do
			ip rule show | grep "from all fwmark 0x90000000\/0xf0000000" | sed -e "s/^\(.*\)\:/ip rule del prio \1/g" | \
				awk '{system($0 " > \/dev\/null 2>\&1")}'
			local_sys_load_balance_wan1_exist=$( ip rule show | grep -c "from all fwmark 0x90000000\/0xf0000000" )
		done
		ip route flush cache > /dev/null 2>&1
		## 不清除系统负载均衡策略中的分流功能，但降低其执行优先级，防止先于自定义分流规则执行
		ip rule add from all fwmark 0x90000000/0xf0000000 table $WAN1 prio "$1" > /dev/null 2>&1
		ip route flush cache > /dev/null 2>&1
	fi
}

## 判断是否有LZ分流IPTV服务运行
## 返回值：
##     1--有
##     0--无
lz_is_lz_rule_iptv_running() {
	[ ! -d ${PATH_BOOTLOADER} ] && return 0
	if [ -f ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} ]; then
		local check_item="$( grep "${PATH_LZ}/lz_rule.sh" ${PATH_BOOTLOADER}/${BOOTLOADER_NAME}  )"
		[ -z "$check_item" ] && return 0
		check_item="$( grep -Eo "iptv_igmp_switch=[0|1]" ${PATH_LZ}/configs/lz_rule_config.sh  )"
		[ -z "$check_item" ] && return 0
		check_item="$( ip route show table $LZ_IPTV | grep default | sed -n 1p )"
		[ -z "$check_item" ] && return 0
	fi
	return 1
}

## 清除系统策略路由库中已有IPTV规则
lz_del_iptv_rule() {
	local iptv_rule_exist=$( ip rule show | grep -c "$IP_RULE_PRIO_IPTV:" )
	if [ $iptv_rule_exist -gt 0 ]; then
		until [ $iptv_rule_exist = 0 ]
		do
			ip rule show | grep "$IP_RULE_PRIO_IPTV:" | sed -e "s/^\("$IP_RULE_PRIO_IPTV"\)\:.*$/ip rule del prio \1/g" | \
				awk '{system($0 " > \/dev\/null 2>\&1")}'
			iptv_rule_exist=$( ip rule show | grep -c "$IP_RULE_PRIO_IPTV:" )
		done
		ip route flush cache > /dev/null 2>&1
	fi
}

## 清空系统中已有IPTV路由表
lz_clear_iptv_route() {
	local iptv_item="$( ip route show table $LZ_IPTV )"
	for iptv_item in $iptv_item
	do
		ip route del $iptv_item table $LZ_IPTV > /dev/null 2>&1
	done
	ip route flush cache > /dev/null 2>&1
}

## 生成IGMP代理配置文件
## 输入项：
##     $1--文件路径
##     $2--IGMP代理配置文件名
##     $3--IPTV线路在路由器内的接口设备ID
## 返回值：
##     0--成功
##     255--失败
lz_create_igmp_proxy_conf() {
	[ -z "$1" -o -z "$2" -o -z "$3" ] && return 255
	if [ ! -d "$1" ]; then
		mkdir -p "$1"
	fi
	cat > "$1"/"$2" <<EOF
phyint $3 upstream ratelimit 0 threshold 1 altnet 0.0.0.0/0
phyint br0 downstream ratelimit 0 threshold 1
EOF
	[ ! -f "$1"/"$2" ] && return 255
	return 0
}

## 设置hnd/axhnd/axhnd.675x平台核心网桥IGMP接口函数
## 输入项：
##     $1--接口标识
##     $2--0：IGMP&MLD；1：IGMP；2：MLD
##     $3--0：disabled；1：standard；2：blocking
## 返回值：
##     0--成功
##     1--失败
lz_set_hnd_bcmmcast_if() {
	local reval=1
	[ -z "$( which bcmmcastctl 2> /dev/null )" ] && return $reval
	[ "$2" != "0" -a "$2" != "1" -a "$2" != "2" ] && return $reval
	[ "$3" != "0" -a "$3" != "1" -a "$3" != "2" ] && return $reval
	[ -n "$1" ] && {
		[ -n "$( bcmmcastctl show 2> /dev/null | grep -w ""$1":" | grep MLD | sed -n 1p )" ] && {
			[ "$2" = "0" -o "$2" = "2" ] && {
				bcmmcastctl rate -i $1 -p 2 -r 0  > /dev/null 2>&1
				bcmmcastctl l2l -i $1 -p 2 -e 1  > /dev/null 2>&1
				bcmmcastctl mode -i $1 -p 2 -m $3  > /dev/null 2>&1 && let reval++
			}
		}
		[ -n "$( bcmmcastctl show 2> /dev/null | grep -w ""$1":" | grep IGMP | sed -n 1p )" ] && {
			[ "$2" = "0" -o "$2" = "1" ] && {
				bcmmcastctl rate -i $1 -p 1 -r 0  > /dev/null 2>&1
				bcmmcastctl l2l -i $1 -p 1 -e 1  > /dev/null 2>&1
				bcmmcastctl mode -i $1 -p 1 -m $3  > /dev/null 2>&1 && let reval++
			}
		}
		[ "$2" = "0" ] && {
			[ "$reval" = "3" ] && reval=0 || reval=1
		}
		[ "$2" = "1" -o "$2" = "2" ] && {
			[ "$reval" = "2" ] && reval=0 || reval=1
		}
	}
	return $reval
}

## 恢复系统原有igmpproxy参数
## 输入项：
##     $1--是否显示执行结果（1--显示；其它符号--禁止显示）
## 返回值：无
lz_restore_sys_igmpproxy_parameters() {
	## 获取系统原生第一WAN口的接口ID标识
	local iptv_ifname="$( nvram get wan0_ifname | grep -Eo 'vlan[0-9]*|eth[0-9]*' | sed -n 1p )"

	## 获取igmpproxy进程信息
	local igmp_filename="$( ps | grep igmpproxy | grep '.conf' | sed -n 1p | awk -F " " '{print $6}' )"
	if [ -n "$igmp_filename" ]; then
		## 判断igmpproxy.conf是否存在
		if [ -f "$igmp_filename" ]; then
			## 判断接口是否存在
			if [ -z "$iptv_ifname" ]; then
				## 接口不存在，杀掉当前进程
				killall igmpproxy > /dev/null 2>&1
			## 判断接口是否符合当前脚本参数设置
			elif [ -z "$( grep "$iptv_ifname" "$igmp_filename" )" ]; then
				## 不符合则需杀掉当前进程
				killall igmpproxy > /dev/null 2>&1

				## 生成IGMP代理配置文件
				## 输入项：
				##     $1--文件路径
				##     $2--IGMP代理配置文件名
				##     $3--IPTV线路在路由器内的接口设备ID
				## 返回值：
				##     0--成功
				##     255--失败
				lz_create_igmp_proxy_conf "/tmp" "igmpproxy.conf" "$iptv_ifname"

				sleep 1s

				## 重新启动igmpproxy代理
				/usr/sbin/igmpproxy /tmp/igmpproxy.conf > /dev/null 2>&1

				if [ "$1" = "1" ]; then
					## 再次获取igmpproxy进程信息
					igmp_filename="$( ps | grep igmpproxy | grep '.conf' | sed -n 1p | awk -F " " '{print $6}' )"
					if [ -n "$igmp_filename" ]; then
						echo $(date) [$$]: IGMPPROXY service \( "$iptv_ifname" \) is running.
						echo $(date) [$$]: IGMPPROXY service \( "$iptv_ifname" \) is running. >> /tmp/syslog.log
					fi
				fi
			else
				## 判断是否使用的是系统原有路径的配置文件
				if [ "$igmp_filename" != "/tmp/igmpproxy.conf" ]; then
					## 不符合则需杀掉当前进程
					killall igmpproxy > /dev/null 2>&1

					## 生成IGMP代理配置文件
					## 输入项：
					##     $1--文件路径
					##     $2--IGMP代理配置文件名
					##     $3--IPTV线路在路由器内的接口设备ID
					## 返回值：
					##     0--成功
					##     255--失败
					lz_create_igmp_proxy_conf "/tmp" "igmpproxy.conf" "$iptv_ifname"

					sleep 1s

					## 重新启动igmpproxy代理
					/usr/sbin/igmpproxy /tmp/igmpproxy.conf > /dev/null 2>&1
				fi

				if [ "$1" = "1" ]; then
					## 再次获取igmpproxy进程信息
					igmp_filename="$( ps | grep igmpproxy | grep '.conf' | sed -n 1p | awk -F " " '{print $6}' )"
					if [ -n "$igmp_filename" ]; then
						echo $(date) [$$]: IGMPPROXY service \( "$iptv_ifname" \) is running.
						echo $(date) [$$]: IGMPPROXY service \( "$iptv_ifname" \) is running. >> /tmp/syslog.log
					fi
				fi
			fi
		else
			## 当前进程的igmpproxy代理文件不存在的错误，需要杀掉当前进程
			killall igmpproxy > /dev/null 2>&1

			if [ -n "$iptv_ifname" ]; then

				## 生成IGMP代理配置文件
				## 输入项：
				##     $1--文件路径
				##     $2--IGMP代理配置文件名
				##     $3--IPTV线路在路由器内的接口设备ID
				## 返回值：
				##     0--成功
				##     255--失败
				lz_create_igmp_proxy_conf "/tmp" "igmpproxy.conf" "$iptv_ifname"

				sleep 1s

				## 重新启动igmpproxy代理
				/usr/sbin/igmpproxy /tmp/igmpproxy.conf > /dev/null 2>&1

				if [ "$1" = "1" ]; then
					## 再次获取igmpproxy进程信息
					igmp_filename="$( ps | grep igmpproxy | grep '.conf' | sed -n 1p | awk -F " " '{print $6}' )"
					if [ -n "$igmp_filename" ]; then
						echo $(date) [$$]: IGMPPROXY service \( "$iptv_ifname" \) is running.
						echo $(date) [$$]: IGMPPROXY service \( "$iptv_ifname" \) is running. >> /tmp/syslog.log
					fi
				fi
			fi
		fi
	else
		## hnd/axhnd/axhnd.675x平台机型无igmpproxy进程
		## 设置hnd/axhnd/axhnd.675x平台核心网桥IGMP接口
		## 输入项：
		##     $1--接口标识
		##     $2--0：IGMP&MLD；1：IGMP；2：MLD
		##     $3--0：disabled；1：standard；2：blocking
		## 返回值：
		##     0--成功
		##     1--失败
		lz_set_hnd_bcmmcast_if "br0" "0" "2"
	fi

	## 清除脚本生成的IGMP代理配置文件
	if [ -f "${PATH_TMP}/igmpproxy.conf" ]; then
		rm ${PATH_TMP}/igmpproxy.conf > /dev/null 2>&1
	fi
}

## 调整和更新udpxy参数
## 输入项：
##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx，nnn--未知接口；x--数字编号）
##     $2--是否显示执行结果（1--显示；其它符号--禁止显示）
## 返回值：无
lz_djust_udpxy_parameters() {
	## 校验输入项参数是否在取值范围内，否则退出
	local iptv_ifname="$( echo "$1" | grep -Eo 'vlan[0-9]*|eth[0-9]*|ppp[0-9]*|nnn' )"
	[ -z "$iptv_ifname" ] && return

	if [ "$iptv_ifname" = "nnn" ]; then
		## 获取系统原生第一WAN口的接口ID标识
		iptv_ifname="$( nvram get wan0_ifname | grep -Eo 'vlan[0-9]*|eth[0-9]*' | sed -n 1p )"
	fi

	## 获取路由器本地IP地址
	local route_local_ip="$( /sbin/ifconfig br0 )"
	route_local_ip="$( echo $route_local_ip | awk -F " " '{print $7}' | awk -F ":" '{print $2}' )"

	## 获取udpxy进程信息
	local udpxy_item="$( ps | grep udpxy | grep '\-m' | sed -n 1p )"

	## 获取udpxy端口号
	local udpxy_enable_x="$( nvram get udpxy_enable_x | grep -Eo '^[1-9][0-9]{0,4}$' | sed -n 1p )"

	## 获取udpxy客户端数量
	local udpxy_clients="$( nvram get udpxy_clients | grep -Eo '^[1-9][0-9]{0,3}$' | sed -n 1p )"

	if [ -z "$udpxy_enable_x" ]; then
		[ -n "$udpxy_item" ] && killall udpxy > /dev/null 2>&1
	elif [ -n "$udpxy_item" ]; then
		if [ -z "$( echo "$udpxy_item" | grep "$iptv_ifname" )" ]; then
			killall udpxy > /dev/null 2>&1
			## 重启udpxy服务
			if [ -n "$iptv_ifname" ]; then
				/usr/sbin/udpxy -m "$iptv_ifname" -p "$udpxy_enable_x" -B 65536 -c "$udpxy_clients" -a br0 > /dev/null 2>&1
			fi
		fi

		if [ "$2" = "1" ]; then
			## 再次获取udpxy进程信息
			udpxy_item="$( ps | grep udpxy | grep '\-m' | sed -n 1p )"
			iptv_ifname="$( ps | grep udpxy | grep '\-m' | sed -n 1p | awk -F '\-m ' '{print $2}' | awk '{print $1}' )"
			if [ -n "$udpxy_item" ]; then
				echo $(date) [$$]: UDPXY service \( "$route_local_ip:$udpxy_enable_x" "$iptv_ifname" \) is running.
				echo $(date) [$$]: UDPXY service \( "$route_local_ip:$udpxy_enable_x" "$iptv_ifname" \) is running. >> /tmp/syslog.log
			fi
		fi
	else
		if [ -n "$iptv_ifname" ]; then
			## 重启udpxy服务
			/usr/sbin/udpxy -m "$iptv_ifname" -p "$udpxy_enable_x" -B 65536 -c "$udpxy_clients" -a br0 > /dev/null 2>&1			
		fi

		if [ "$2" = "1" ]; then
			## 再次获取udpxy进程信息
			udpxy_item="$( ps | grep udpxy | grep '\-m' | sed -n 1p )"
			iptv_ifname="$( ps | grep udpxy | grep '\-m' | sed -n 1p | awk -F '\-m ' '{print $2}' | awk '{print $1}' )"
			if [ -n "$udpxy_item" ]; then
				echo $(date) [$$]: UDPXY service \( "$route_local_ip:$udpxy_enable_x" "$iptv_ifname" \) is running.
				echo $(date) [$$]: UDPXY service \( "$route_local_ip:$udpxy_enable_x" "$iptv_ifname" \) is running. >> /tmp/syslog.log
			fi
		fi
	fi
}

## 恢复系统原有IPTV服务
## 输入项：
##     $1--是否显示执行结果（1--显示；其它符号--禁止显示）
## 返回值：无
lz_restore_sys_iptv_services() {
	## 恢复系统原有igmpproxy参数
	## 输入项：
	##     $1--是否显示执行结果（1--显示；其它符号--禁止显示）
	## 返回值：无
	lz_restore_sys_igmpproxy_parameters "$1"

	## 恢复系统原有udpxy参数
	## 调整和更新udpxy参数
	## 输入项：
	##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx，nnn--未知接口；x--数字编号）
	##     $2--是否显示执行结果（1--显示；其它符号--禁止显示）
	## 返回值：无
	lz_djust_udpxy_parameters "nnn" "$1"
}

## 初始化单臂路由VLAN参数
## 输入项：
##     全局变量
## 返回值：
##     0--成功
##     1--失败
lz_Initialize_vlan_parameters() {
	## VLAN_ID参数值校验
	## 第一WAN口
	wan1_1_vlan_id="$( echo "$wan1_1_vlan_id" | grep -Eo '[0-9]{1,4}' | sed -n 1p )"
	[ -z "$wan1_1_vlan_id" ] && wan1_1_vlan_id="0"
	[ "$wan1_1_vlan_id" -lt "0" -o "$wan1_1_vlan_id" -gt "4095" ] && wan1_1_vlan_id="0"
	wan1_2_vlan_id="$( echo "$wan1_2_vlan_id" | grep -Eo '[0-9]{1,4}' | sed -n 1p )"
	[ -z "$wan1_2_vlan_id" ] && wan1_2_vlan_id="0"
	[ "$wan1_2_vlan_id" -lt "0" -o "$wan1_2_vlan_id" -gt "4095" ] && wan1_2_vlan_id="0"
	wan1_3_vlan_id="$( echo "$wan1_3_vlan_id" | grep -Eo '[0-9]{1,4}' | sed -n 1p )"
	[ -z "$wan1_3_vlan_id" ] && wan1_3_vlan_id="0"
	[ "$wan1_3_vlan_id" -lt "0" -o "$wan1_3_vlan_id" -gt "4095" ] && wan1_3_vlan_id="0"
	wan1_4_vlan_id="$( echo "$wan1_4_vlan_id" | grep -Eo '[0-9]{1,4}' | sed -n 1p )"
	[ -z "$wan1_4_vlan_id" ] && wan1_4_vlan_id="0"
	[ "$wan1_4_vlan_id" -lt "0" -o "$wan1_4_vlan_id" -gt "4095" ] && wan1_4_vlan_id="0"

	## 第二WAN口
	wan2_1_vlan_id="$( echo "$wan2_1_vlan_id" | grep -Eo '[0-9]{1,4}' | sed -n 1p )"
	[ -z "$wan2_1_vlan_id" ] && wan2_1_vlan_id="0"
	[ "$wan2_1_vlan_id" -lt "0" -o "$wan2_1_vlan_id" -gt "4095" ] && wan2_1_vlan_id="0"
	wan2_2_vlan_id="$( echo "$wan2_2_vlan_id" | grep -Eo '[0-9]{1,4}' | sed -n 1p )"
	[ -z "$wan2_2_vlan_id" ] && wan2_2_vlan_id="0"
	[ "$wan2_2_vlan_id" -lt "0" -o "$wan2_2_vlan_id" -gt "4095" ] && wan2_2_vlan_id="0"
	wan2_3_vlan_id="$( echo "$wan2_3_vlan_id" | grep -Eo '[0-9]{1,4}' | sed -n 1p )"
	[ -z "$wan2_3_vlan_id" ] && wan2_3_vlan_id="0"
	[ "$wan2_3_vlan_id" -lt "0" -o "$wan2_3_vlan_id" -gt "4095" ] && wan2_3_vlan_id="0"
	wan2_4_vlan_id="$( echo "$wan2_4_vlan_id" | grep -Eo '[0-9]{1,4}' | sed -n 1p )"
	[ -z "$wan2_4_vlan_id" ] && wan2_4_vlan_id="0"
	[ "$wan2_4_vlan_id" -lt "0" -o "$wan2_4_vlan_id" -gt "4095" ] && wan2_4_vlan_id="0"

	## 各VLAN_ID参数值在非0时不可相等
	[ "$wan1_1_vlan_id" != "0" ] && {
		[ "$wan1_1_vlan_id" = "$wan1_2_vlan_id" ] && return 1
		[ "$wan1_1_vlan_id" = "$wan1_3_vlan_id" ] && return 1
		[ "$wan1_1_vlan_id" = "$wan1_4_vlan_id" ] && return 1
		[ "$wan1_1_vlan_id" = "$wan2_1_vlan_id" ] && return 1
		[ "$wan1_1_vlan_id" = "$wan2_2_vlan_id" ] && return 1
		[ "$wan1_1_vlan_id" = "$wan2_3_vlan_id" ] && return 1
		[ "$wan1_1_vlan_id" = "$wan2_4_vlan_id" ] && return 1
	}
	[ "$wan1_2_vlan_id" != "0" ] && {
		[ "$wan1_2_vlan_id" = "$wan1_3_vlan_id" ] && return 1
		[ "$wan1_2_vlan_id" = "$wan1_4_vlan_id" ] && return 1
		[ "$wan1_2_vlan_id" = "$wan2_1_vlan_id" ] && return 1
		[ "$wan1_2_vlan_id" = "$wan2_2_vlan_id" ] && return 1
		[ "$wan1_2_vlan_id" = "$wan2_3_vlan_id" ] && return 1
		[ "$wan1_2_vlan_id" = "$wan2_4_vlan_id" ] && return 1
	}
	[ "$wan1_3_vlan_id" != "0" ] && {
		[ "$wan1_3_vlan_id" = "$wan1_4_vlan_id" ] && return 1
		[ "$wan1_3_vlan_id" = "$wan2_1_vlan_id" ] && return 1
		[ "$wan1_3_vlan_id" = "$wan2_2_vlan_id" ] && return 1
		[ "$wan1_3_vlan_id" = "$wan2_3_vlan_id" ] && return 1
		[ "$wan1_3_vlan_id" = "$wan2_4_vlan_id" ] && return 1
	}
	[ "$wan1_4_vlan_id" != "0" ] && {
		[ "$wan1_4_vlan_id" = "$wan2_1_vlan_id" ] && return 1
		[ "$wan1_4_vlan_id" = "$wan2_2_vlan_id" ] && return 1
		[ "$wan1_4_vlan_id" = "$wan2_3_vlan_id" ] && return 1
		[ "$wan1_4_vlan_id" = "$wan2_4_vlan_id" ] && return 1
	}
	[ "$wan2_1_vlan_id" != "0" ] && {
		[ "$wan2_1_vlan_id" = "$wan2_2_vlan_id" ] && return 1
		[ "$wan2_1_vlan_id" = "$wan2_3_vlan_id" ] && return 1
		[ "$wan2_1_vlan_id" = "$wan2_4_vlan_id" ] && return 1
	}
	[ "$wan2_2_vlan_id" != "0" ] && {
		[ "$wan2_2_vlan_id" = "$wan2_3_vlan_id" ] && return 1
		[ "$wan2_2_vlan_id" = "$wan2_4_vlan_id" ] && return 1
	}
	[ "$wan2_3_vlan_id" != "0" -a "$wan2_3_vlan_id" = "$wan2_4_vlan_id" ] && return 1

	return 0
}

## 判断是否有LZ分流服务运行
## 返回值：
##     1--有
##     0--无
lz_is_lz_rule_running() {
	[ ! -d ${PATH_BOOTLOADER} ] && return 0

	if [ -f ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} ]; then
		local bootloader_scripts="$( grep "${PATH_LZ}/lz_rule.sh" ${PATH_BOOTLOADER}/${BOOTLOADER_NAME}  )"
		if [ -n "$bootloader_scripts" ]; then
			## 检查系统策略路由库里是否有正在运行的LZ分流脚本的规则
			local local_ip_rule_prio_no=$(( $IP_RULE_PRIO_OPENVPN + 1 ))
			until [ $local_ip_rule_prio_no -gt $IP_RULE_PRIO ]
			do
				local total_num=$( ip rule show | grep -c "$local_ip_rule_prio_no:" )
				[ $total_num -gt 0 ] && return 1
				local_ip_rule_prio_no=$(( $local_ip_rule_prio_no + 1 ))
			done
		fi
	fi

	return 0
}

## 清理OpenVPN服务子网出口规则
lz_clear_openvpn_rule() {
	## 判断是否有LZ分流服务运行
	## 返回值：
	##     1--有
	##     0--无
	lz_is_lz_rule_running
	if [ "$?" = "0" ]; then
		## 清空策略优先级为IP_RULE_PRIO_OPENVPN的出口规则
		ip rule show | grep "$IP_RULE_PRIO_OPENVPN:" | sed -e "s/^\("$IP_RULE_PRIO_OPENVPN"\):.*$/ip rule del prio \1/g" | \
			awk '{system($0 " > \/dev\/null 2>\&1")}'
		ip route flush cache > /dev/null 2>&1
	fi
}

## 清除openvpn-event中命令行
lz_clear_openvpn_event_command() {
	## 判断是否有LZ分流服务运行
	## 返回值：
	##     1--有
	##     0--无
	lz_is_lz_rule_running
	if [ "$?" = "0" ]; then
		if [ -f ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} ]; then
			sed -i '/By LZ/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/!!!/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/lz_openvpn_exist/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/lz_tun_number/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/lz_ip_route/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/lz_ovs_client_wan/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/lz_ovs_client_wan_port/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/lz_ovs_client_wan_used/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/lz_openvpn_subnet/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i '/lz_tun_sub_list/d' ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
			sed -i "/"${OPENVPN_EVENT_NAME}"/d" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} > /dev/null 2>&1
		fi
	fi
}

## 清除firewall-start中脚本引导项
lz_clear_firewall_start_command() {
	if [ -f ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} ]; then
		sed -i "/"${PROJECT_FILENAME}"/d" ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} > /dev/null 2>&1
	fi
}

## 关闭路由器内全部对外VLAN接口
## 输入项：
##     $1--路由器内网桥标识
## 返回值：
##     0--成功
##     1--失败
##     255--参数内容为空
lz_close_all_route_vlan_if() {
	[ -z "$1" ] && return 255
	if [ -f "/proc/net/vlan/config" ]; then
		local if_item="$( grep -Eo '^.*[\.][0-9]{1,4}' "/proc/net/vlan/config" | awk '{print $1}' )"
		for if_item in $if_item
		do
			ifconfig "$if_item" down > /dev/null 2>&1
			brctl delif "$1" "$if_item" > /dev/null 2>&1
			vconfig rem "$if_item" > /dev/null 2>&1
		done
		return 0
	fi
	return 1
}

## 关闭路由器内指定对外VLAN接口
## 输入项：
##     $1--WAN口接口设备标识
##     $2--所接网络VLAN_ID值
##     $3--路由器内网桥标识
## 返回值：无
lz_close_route_vlan_if() {
	[ -z "$1" -o -z "$2" -o -z "$3" ] && return
	[ "$2" = "0" ] && return
	ifconfig "$1"."$2" down > /dev/null 2>&1
	brctl delif "$3" "$1"."$2" > /dev/null 2>&1
	vconfig rem "$1"."$2" > /dev/null 2>&1
}

## 创建firewall-start启动文件并添加脚本引导项
lz_create_firewall_start_command() {
	if [ ! -d ${PATH_BOOTLOADER} ]; then
		mkdir -p ${PATH_BOOTLOADER}
	fi

	if [ ! -f ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} ]; then
		cat > ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} <<EOF
#!/bin/sh
EOF
	fi

	local bootloader_scripts="$( grep "${PROJECT_FILENAME}" ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} )"
	if [ -z "$bootloader_scripts" ]; then
		sed -i "1a "${PATH_LZ}/${PROJECT_FILENAME}"" ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} > /dev/null 2>&1
	fi

	chmod +x ${PATH_BOOTLOADER}/${BOOTLOADER_NAME} > /dev/null 2>&1
}

## 设置并启动路由器VLAN接口
## 输入项：
##     $1--WAN口接口设备标识
##     $2--所接网络VLAN_ID值
##     $3--路由器内网桥标识
## 返回值：无
lz_setup_route_vlan_if() {
	[ -z "$1" -o -z "$2" -o -z "$3" ] && return
	[ "$2" = "0" ] && return
	vconfig add "$1" "$2"
	brctl addif "$3" "$1"."$2" > /dev/null 2>&1
	ifconfig "$1"."$2" up > /dev/null 2>&1
}

## 显示输出VLAN接口状态信息
## 输入项：
##     全局变量
## 返回值：无
lz_display_output_vlan_interface_status_infor() {
	[ ! -f "/proc/net/vlan/config" ] && return
	echo $(date) [$$]: ------------------------------------------
	echo $(date) [$$]: ------------------------------------------------- >> /tmp/syslog.log
	local vlan_mark=0
	local vlan_information="$( cat "/proc/net/vlan/config" )"
	lz_local_space() {
		local local_space="   "
		[ "$1" -gt "9" ] && local_space="  "
		[ "$1" -gt "99" ] && local_space=" "
		[ "$1" -gt "999" ] && local_space=""
		echo "$local_space"
	}
	if [ -n "$wan0_ifname" -a -n "$wan1_1_vlan_id" ]; then
		[ -n "$( echo $vlan_information | grep -o "$wan0_ifname\.$wan1_1_vlan_id" | sed -n 1p )" ] && {
			echo $(date) [$$]: "  Primary WAN    1#  $wan0_ifname.$wan1_1_vlan_id$( lz_local_space $wan1_1_vlan_id )  VID $wan1_1_vlan_id"
			echo $(date) [$$]: "  Primary WAN    1#  $wan0_ifname.$wan1_1_vlan_id$( lz_local_space $wan1_1_vlan_id )  VID $wan1_1_vlan_id" >> /tmp/syslog.log
			vlan_mark=1
		}
	fi
	if [ -n "$wan0_ifname" -a -n "$wan1_2_vlan_id" ]; then
		[ -n "$( echo $vlan_information | grep -o "$wan0_ifname\.$wan1_2_vlan_id" | sed -n 1p )" ] && {
			echo $(date) [$$]: "  Primary WAN    2#  $wan0_ifname.$wan1_2_vlan_id$( lz_local_space $wan1_2_vlan_id )  VID $wan1_2_vlan_id"
			echo $(date) [$$]: "  Primary WAN    2#  $wan0_ifname.$wan1_2_vlan_id$( lz_local_space $wan1_2_vlan_id )  VID $wan1_2_vlan_id" >> /tmp/syslog.log
			vlan_mark=1
		}
	fi
	if [ -n "$wan0_ifname" -a -n "$wan1_3_vlan_id" ]; then
		[ -n "$( echo $vlan_information | grep -o "$wan0_ifname\.$wan1_3_vlan_id" | sed -n 1p )" ] && {
			echo $(date) [$$]: "  Primary WAN    3#  $wan0_ifname.$wan1_3_vlan_id$( lz_local_space $wan1_3_vlan_id )  VID $wan1_3_vlan_id"
			echo $(date) [$$]: "  Primary WAN    3#  $wan0_ifname.$wan1_3_vlan_id$( lz_local_space $wan1_3_vlan_id )  VID $wan1_3_vlan_id" >> /tmp/syslog.log
			vlan_mark=1
		}
	fi
	if [ -n "$wan0_ifname" -a -n "$wan1_4_vlan_id" ]; then
		[ -n "$( echo $vlan_information | grep -o "$wan0_ifname\.$wan1_4_vlan_id" | sed -n 1p )" ] && {
			echo $(date) [$$]: "  Primary WAN    4#  $wan0_ifname.$wan1_4_vlan_id$( lz_local_space $wan1_4_vlan_id )  VID $wan1_4_vlan_id"
			echo $(date) [$$]: "  Primary WAN    4#  $wan0_ifname.$wan1_4_vlan_id$( lz_local_space $wan1_4_vlan_id )  VID $wan1_4_vlan_id" >> /tmp/syslog.log
			vlan_mark=1
		}
	fi
	if [ -n "$wan1_ifname" -a -n "$wan2_1_vlan_id" ]; then
		[ -n "$( echo $vlan_information | grep -o "$wan1_ifname\.$wan2_1_vlan_id" | sed -n 1p )" ] && {
			echo $(date) [$$]: "  Secondary WAN  1#  $wan1_ifname.$wan2_1_vlan_id$( lz_local_space $wan2_1_vlan_id )  VID $wan2_1_vlan_id"
			echo $(date) [$$]: "  Secondary WAN  1#  $wan1_ifname.$wan2_1_vlan_id$( lz_local_space $wan2_1_vlan_id )  VID $wan2_1_vlan_id" >> /tmp/syslog.log
			vlan_mark=1
		}
	fi
	if [ -n "$wan1_ifname" -a -n "$wan2_2_vlan_id" ]; then
		[ -n "$( echo $vlan_information | grep -o "$wan1_ifname\.$wan2_2_vlan_id" | sed -n 1p )" ] && {
			echo $(date) [$$]: "  Secondary WAN  2#  $wan1_ifname.$wan2_2_vlan_id$( lz_local_space $wan2_2_vlan_id )  VID $wan2_2_vlan_id"
			echo $(date) [$$]: "  Secondary WAN  2#  $wan1_ifname.$wan2_2_vlan_id$( lz_local_space $wan2_2_vlan_id )  VID $wan2_2_vlan_id" >> /tmp/syslog.log
			vlan_mark=1
		}
	fi
	if [ -n "$wan1_ifname" -a -n "$wan2_3_vlan_id" ]; then
		[ -n "$( echo $vlan_information | grep -o "$wan1_ifname\.$wan2_3_vlan_id" | sed -n 1p )" ] && {
			echo $(date) [$$]: "  Secondary WAN  3#  $wan1_ifname.$wan2_3_vlan_id$( lz_local_space $wan2_3_vlan_id )  VID $wan2_3_vlan_id"
			echo $(date) [$$]: "  Secondary WAN  3#  $wan1_ifname.$wan2_3_vlan_id$( lz_local_space $wan2_3_vlan_id )  VID $wan2_3_vlan_id" >> /tmp/syslog.log
			vlan_mark=1
		}
	fi
	if [ -n "$wan1_ifname" -a -n "$wan2_4_vlan_id" ]; then
		[ -n "$( echo $vlan_information | grep -o "$wan1_ifname\.$wan2_4_vlan_id" | sed -n 1p )" ] && {
			echo $(date) [$$]: "  Secondary WAN  4#  $wan1_ifname.$wan2_4_vlan_id$( lz_local_space $wan2_4_vlan_id )  VID $wan2_4_vlan_id"
			echo $(date) [$$]: "  Secondary WAN  4#  $wan1_ifname.$wan2_4_vlan_id$( lz_local_space $wan2_4_vlan_id )  VID $wan2_4_vlan_id" >> /tmp/syslog.log
			vlan_mark=1
		}
	fi
	if [ "$vlan_mark" = "0" ]; then
			echo $(date) [$$]: "  No VLAN interface set"
			echo $(date) [$$]: "  No VLAN interface set" >> /tmp/syslog.log
	fi
	echo $(date) [$$]: ------------------------------------------
	echo $(date) [$$]: ------------------------------------------------- >> /tmp/syslog.log
}

## 向系统策略路由库中添加双向访问网络路径规则
## 输入项：
##     $1--IPv4网址/网段地址列表全路径文件名
##     $2--路由表ID
##     $3--IP规则优先级
## 返回值：无
lz_add_dual_ip_rules() {
	sed -e 's/\(^[^#]*\)[#].*$/\1/g' -e '/^$/d' -e 's/LZ/  /g' -e 's/ip/  /g' \
	-e 's/\(\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}\)/LZ\1LZ/g' \
	-e 's/^.*\(LZ\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}LZ\).*$/\1/g' \
	-e '/^[^L][^Z]/d' -e '/[^L][^Z]$/d' -e '/^.\{0,10\}$/d' \
	-e '/[3-9][0-9][0-9]/d' -e '/[2][6-9][0-9]/d' -e '/[2][5][6-9]/d' -e '/[\/][4-9][0-9]/d' \
	-e '/[\/][3][3-9]/d' \
	-e "s/^LZ\(.*\)LZ$/ip rule add from \1 table "$2" prio "$3"/g" \
	-e '/^[^i]/d' \
	-e '/^[i][^p]/d' "$1" | \
	awk '{system($0 " > \/dev\/null 2>\&1")}'
	sed -e 's/\(^[^#]*\)[#].*$/\1/g' -e '/^$/d' -e 's/LZ/  /g' -e 's/ip/  /g' \
	-e 's/\(\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}\)/LZ\1LZ/g' \
	-e 's/^.*\(LZ\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}LZ\).*$/\1/g' \
	-e '/^[^L][^Z]/d' -e '/[^L][^Z]$/d' -e '/^.\{0,10\}$/d' \
	-e '/[3-9][0-9][0-9]/d' -e '/[2][6-9][0-9]/d' -e '/[2][5][6-9]/d' -e '/[\/][4-9][0-9]/d' \
	-e '/[\/][3][3-9]/d' \
	-e "s/^LZ\(.*\)LZ$/ip rule add from all to \1 table "$2" prio "$3"/g" \
	-e '/^[^i]/d' \
	-e '/^[i][^p]/d' "$1" | \
	awk '{system($0 " > \/dev\/null 2>\&1")}'
}

## 获取IPv4网址/网段地址列表文件中的列表数据
## 输入项：
##     $1--IPv4网址/网段地址列表全路径文件名
## 返回值：
##     数据列表
lz_get_ipv4_list_from_data_file() {
	sed -e 's/\(^[^#]*\)[#].*$/\1/g' -e '/^$/d' -e 's/LZ/  /g' \
	-e 's/\(\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}\)/LZ\1LZ/g' \
	-e 's/^.*\(LZ\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}LZ\).*$/\1/g' \
	-e '/^[^L][^Z]/d' -e '/[^L][^Z]$/d' -e '/^.\{0,10\}$/d' \
	-e '/[3-9][0-9][0-9]/d' -e '/[2][6-9][0-9]/d' -e '/[2][5][6-9]/d' -e '/[\/][4-9][0-9]/d' \
	-e '/[\/][3][3-9]/d' \
	-e "s/^LZ\(.*\)LZ$/\1/g" "$1"
}

## 添加从源地址到目标地址列表访问网络路径规则
## 输入项：
##     $1--IPv4源网址/网段地址
##     $2--IPv4目标网址/网段地址列表全路径文件名
##     $3--路由表ID
##     $4--IP规则优先级
## 返回值：无
lz_add_src_to_dst_sets_ip_rules() {
	sed -e 's/\(^[^#]*\)[#].*$/\1/g' -e '/^$/d' -e 's/LZ/  /g' -e 's/ip/  /g' \
	-e 's/\(\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}\)/LZ\1LZ/g' \
	-e 's/^.*\(LZ\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}LZ\).*$/\1/g' \
	-e '/^[^L][^Z]/d' -e '/[^L][^Z]$/d' -e '/^.\{0,10\}$/d' \
	-e '/[3-9][0-9][0-9]/d' -e '/[2][6-9][0-9]/d' -e '/[2][5][6-9]/d' -e '/[\/][4-9][0-9]/d' \
	-e '/[\/][3][3-9]/d' \
	-e "s/^LZ\(.*\)LZ$/ip rule add from "$1" to \1 table "$3" prio "$4"/g" \
	-e '/^[^i]/d' \
	-e '/^[i][^p]/d' "$2" | \
	awk '{system($0 " > \/dev\/null 2>\&1")}'
}

## 添加从源地址列表到目标地址访问网络路径规则
## 输入项：
##     $1--IPv4源网址/网段地址列表全路径文件名
##     $2--IPv4目标网址/网段地址
##     $3--路由表ID
##     $4--IP规则优先级
## 返回值：无
lz_add_src_sets_to_dst_ip_rules() {
	sed -e 's/\(^[^#]*\)[#].*$/\1/g' -e '/^$/d' -e 's/LZ/  /g' -e 's/ip/  /g' \
	-e 's/\(\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}\)/LZ\1LZ/g' \
	-e 's/^.*\(LZ\([0-9]\{1,3\}[\.]\)\{3\}[0-9]\{1,3\}\([\/][0-9]\{1,2\}\)\{0,1\}LZ\).*$/\1/g' \
	-e '/^[^L][^Z]/d' -e '/[^L][^Z]$/d' -e '/^.\{0,10\}$/d' \
	-e '/[3-9][0-9][0-9]/d' -e '/[2][6-9][0-9]/d' -e '/[2][5][6-9]/d' -e '/[\/][4-9][0-9]/d' \
	-e '/[\/][3][3-9]/d' \
	-e "s/^LZ\(.*\)LZ$/ip rule add from \1 to "$2" table "$3" prio "$4"/g" \
	-e '/^[^i]/d' \
	-e '/^[i][^p]/d' "$1" | \
	awk '{system($0 " > \/dev\/null 2>\&1")}'
}

## 调整和更新igmpproxy参数
## 输入项：
##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx；x--数字编号）
## 返回值：无
lz_djust_igmpproxy_parameters() {
	## 校验输入项参数是否在取值范围内，否则退出
	[ -z "$( echo "$1" | grep -E 'vlan[0-9]*|eth[0-9]*|ppp[0-9]*' )" ] && return

	## 获取igmpproxy进程信息
	local igmp_filename="$( ps | grep igmpproxy | grep '.conf' | sed -n 1p | awk -F " " '{print $6}' )"
	if [ -n "$igmp_filename" ]; then
		if [ -f "$igmp_filename" ]; then
			## 判断接口是否符合当前脚本参数设置
			if [ -z "$( grep "$1" "$igmp_filename" )" ]; then
				## 不符合则需杀掉当前进程
				killall igmpproxy > /dev/null 2>&1

				## 生成IGMP代理配置文件
				## 输入项：
				##     $1--文件路径
				##     $2--IGMP代理配置文件名
				##     $3--IPTV线路在路由器内的接口设备ID
				## 返回值：
				##     0--成功
				##     255--失败
				lz_create_igmp_proxy_conf "${PATH_TMP}" "igmpproxy.conf" "$1"

				sleep 1s

				## 重新启动igmpproxy代理
				/usr/sbin/igmpproxy ${PATH_TMP}/igmpproxy.conf > /dev/null 2>&1

				## 再次获取igmpproxy进程信息
				igmp_filename="$( ps | grep igmpproxy | grep '.conf' | sed -n 1p | awk -F " " '{print $6}' )"
				if [ -n "$igmp_filename" ]; then
					echo $(date) [$$]: IGMPPROXY service \( "$1" \) is running.
					echo $(date) [$$]: IGMPPROXY service \( "$1" \) is running. >> /tmp/syslog.log
				fi
			else
				echo $(date) [$$]: IGMPPROXY service \( "$1" \) is running.
				echo $(date) [$$]: IGMPPROXY service \( "$1" \) is running. >> /tmp/syslog.log
			fi
		fi
	else
		## hnd/axhnd/axhnd.675x平台机型无igmpproxy进程
		## 设置hnd/axhnd/axhnd.675x平台核心网桥IGMP接口
		## 输入项：
		##     $1--接口标识
		##     $2--0：IGMP&MLD；1：IGMP；2：MLD
		##     $3--0：disabled；1：standard；2：blocking
		## 返回值：
		##     0--成功
		##     1--失败
		lz_set_hnd_bcmmcast_if "br0" "0" "$hnd_br0_bcmmcast_mode"
	fi
}

## IPTV服务支持
## 输入项：
##     $1--第一WAN口接口设备标识
##     $2--第二WAN口接口设备标识
##     全局变量
## 返回值：无
lz_iptv_support() {
	[ "$iptv_stb_wan" != "1" -a "$iptv_stb_wan" != "2" ] && return

	## 获取WAN口接口设备标识
	local wan0_ifname="$1"
	local wan1_ifname="$2"

	## 获取WAN口接口设备网关地址
	local wan0_xgateway="$( nvram get wan0_xgateway | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sed -n 1p )"
	local wan1_xgateway="$( nvram get wan1_xgateway | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sed -n 1p )"

	## 判断路由器是否采用双线路双WAN口接入，获取IPTV线路在路由器内的接口设备ID和IPTV网关地址
	local iptv_wan_id=$WAN0
	local iptv_interface_id="$wan0_ifname"
	local iptv_getway_ip="$wan0_xgateway"
	if [ $iptv_stb_wan = 2 ]; then
		iptv_wan_id=$WAN1
		iptv_interface_id="$wan1_ifname"
		iptv_getway_ip="$wan1_xgateway"
	fi
	if [ -n "$( ip route | grep nexthop | sed -n 1p )" ]; then
		if [ $iptv_stb_get_ip_mode = 3 ]; then
			iptv_interface_id="$( ip route show table $iptv_wan_id | grep default | grep -Eo 'ppp[0-9]*' | sed -n 1p )"
			iptv_getway_ip="$( ip route show table $iptv_wan_id | grep default | grep "$iptv_interface_id" | awk -F " " '{print $3}' | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sed -n 1p )"
			if [ -z "$iptv_interface_id" -o -z "$iptv_getway_ip" ]; then
				iptv_interface_id="$wan0_ifname"
				iptv_getway_ip="$wan0_xgateway"
				if [ $iptv_stb_wan = 2 ]; then
					iptv_interface_id="$wan1_ifname"
					iptv_getway_ip="$wan1_xgateway"
				fi
			fi
		fi
	else
		## 单线接入
		if [ $iptv_stb_get_ip_mode = 3 ]; then
			iptv_interface_id="$( ip route | grep default | grep -Eo 'ppp[0-9]*' | sed -n 1p )"
			iptv_getway_ip="$( ip route | grep default | grep "$iptv_interface_id" | awk -F " " '{print $3}' | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sed -n 1p )"
			if [ -z "$iptv_interface_id" -o -z "$iptv_getway_ip" ]; then
				iptv_interface_id="$wan0_ifname"
				iptv_getway_ip="$wan0_xgateway"
				if [ $iptv_stb_wan = 2 ]; then
					iptv_interface_id="$wan1_ifname"
					iptv_getway_ip="$wan1_xgateway"
				fi
			fi
		fi
		if [ -z "$iptv_interface_id" -o -z "$iptv_getway_ip" ]; then
			iptv_interface_id="$wan1_ifname"
			iptv_getway_ip="$wan1_xgateway"
			if [ $iptv_stb_wan = 2 ]; then
				iptv_interface_id="$wan0_ifname"
				iptv_getway_ip="$wan0_xgateway"
			fi
		fi
	fi

	if [ -n "$iptv_interface_id" -a -n "$iptv_getway_ip" ]; then
		## 向系统策略路由库中添加双向访问网络路径规则
		## 输入项：
		##     $1--IPv4网址/网段地址列表全路径文件名
		##     $2--路由表ID
		##     $3--IP规则优先级
		## 返回值：无
		if [ "$iptv_stb_access_mode" = "1" ]; then
			if [ -f "/tmp/lz_iptv_box_ip.lst" ]; then
				## 添加IPTV双向访问网络路径规则
				lz_add_dual_ip_rules "/tmp/lz_iptv_box_ip.lst" "$LZ_IPTV" "$IP_RULE_PRIO_IPTV"
			fi
		else
			if [ -f "/tmp/lz_iptv_box_ip.lst" -a -f "/tmp/lz_iptv_ip_addr.lst" ]; then
				## 获取IPv4网址/网段地址列表文件中的列表数据
				## 输入项：
				##     $1--IPv4网址/网段地址列表全路径文件名
				## 返回值：
				##     数据列表
				for ip_list_item in $( lz_get_ipv4_list_from_data_file "/tmp/lz_iptv_box_ip.lst" )
				do
					## 添加从源地址到目标地址列表访问网络路径规则
					## 输入项：
					##     $1--IPv4源网址/网段地址
					##     $2--IPv4目标网址/网段地址列表全路径文件名
					##     $3--路由表ID
					##     $4--IP规则优先级
					## 返回值：无
					lz_add_src_to_dst_sets_ip_rules "$ip_list_item" "/tmp/lz_iptv_ip_addr.lst" "$LZ_IPTV" "$IP_RULE_PRIO_IPTV"
				done

				## 获取IPv4网址/网段地址列表文件中的列表数据
				## 输入项：
				##     $1--IPv4网址/网段地址列表全路径文件名
				## 返回值：
				##     数据列表
				for ip_list_item in $( lz_get_ipv4_list_from_data_file "/tmp/lz_iptv_box_ip.lst" )
				do
					## 添加从源地址列表到目标地址访问网络路径规则
					## 输入项：
					##     $1--IPv4源网址/网段地址列表全路径文件名
					##     $2--IPv4目标网址/网段地址
					##     $3--路由表ID
					##     $4--IP规则优先级
					## 返回值：无
					lz_add_src_sets_to_dst_ip_rules "/tmp/lz_iptv_ip_addr.lst" "$ip_list_item" "$LZ_IPTV" "$IP_RULE_PRIO_IPTV"
				done
			fi
		fi

		## 向IPTV路由表中添加路由项
		ip route | grep -Ev 'default|nexthop' | \
			sed -e "s/^.*$/ip route add & table "$LZ_IPTV"/g" | \
			awk '{system($0 " > \/dev\/null 2>\&1")}'
		ip route add default via $iptv_getway_ip dev $iptv_interface_id table $LZ_IPTV > /dev/null 2>&1

		## 刷新路由器路由表缓存
		ip route flush cache > /dev/null 2>&1

		## 判断是否已接入指定的IPTV接口设备
		if [ -n "$( ip route show table $LZ_IPTV | grep default )" ]; then
			if [ "$( ip rule show | grep -c "$IP_RULE_PRIO_IPTV:" )" -gt "0" ]; then
				## 调整和更新igmpproxy参数
				## 输入项：
				##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx；x--数字编号）
				## 返回值：无
				lz_djust_igmpproxy_parameters "$iptv_interface_id"
			else
				## 清空系统中已有IPTV路由表
				lz_clear_iptv_route

				## 刷新路由器路由表缓存
				ip route flush cache > /dev/null 2>&1
			fi

			## 调整和更新udpxy参数
			## 输入项：
			##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx，nnn--未知接口；x--数字编号）
			##     $2--是否显示执行结果（1--显示；其它符号--禁止显示）
			## 返回值：无
			lz_djust_udpxy_parameters "$iptv_interface_id" "1"

			if [ "$( ip rule show | grep -c "$IP_RULE_PRIO_IPTV:" )" -gt "0" ]; then
				echo $(date) [$$]: "IPTV STB can be connected to $iptv_interface_id interface for use."
				echo $(date) [$$]: "IPTV STB can be connected to $iptv_interface_id interface for use." >> /tmp/syslog.log
			else
				if [ "$iptv_stb_access_mode" = "1" ]; then
					echo $(date) [$$]: "The IP address of the STB is not set !!!"
					echo $(date) [$$]: "The IP address of the STB is not set !!!" >> /tmp/syslog.log
				else
					echo $(date) [$$]: "No IPTV service address for STB !!!"
					echo $(date) [$$]: "No IPTV service address for STB !!!" >> /tmp/syslog.log
				fi
			fi
		else
			## 清除系统策略路由库中已有IPTV规则
			lz_del_iptv_rule

			## 清空系统中已有IPTV路由表
			lz_clear_iptv_route

			## 刷新路由器路由表缓存
			ip route flush cache > /dev/null 2>&1

			echo $(date) [$$]: "Connection $iptv_interface_id IPTV interface failure !!!"
			echo $(date) [$$]: "Connection $iptv_interface_id IPTV interface failure !!!" >> /tmp/syslog.log
		fi

	else
		## 在路由器内无法获取到IPTV线路的接口设备ID
		if [ -z "$iptv_interface_id" ]; then
			echo $(date) [$$]: "Unable to get IPTV network interface !!!"
			echo $(date) [$$]: "Unable to get IPTV network interface !!!" >> /tmp/syslog.log
		fi

		## 在路由器内无法获取到IPTV线路的网关地址
		if [ -z "$iptv_getway_ip" ]; then
			echo $(date) [$$]: "Unable to get gateway address for IPTV network !!!"
			echo $(date) [$$]: "Unable to get gateway address for IPTV network !!!" >> /tmp/syslog.log
		fi
	fi
}

## 填写openvpn-event事件触发文件内容并添加路由规则项脚本
lz_add_openvpn_event_scripts() {
	local ln=1
	sed -i ""$ln"a \# "${OPENVPN_EVENT_NAME}" for IPTV "$LZ_VERSION"" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))
	sed -i ""$ln"a \# By LZ 妙妙呜 \(larsonzhang\@gmail\.com\)" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))
	sed -i ""$ln"a \# Do not manually modify!!!" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))
	sed -i ""$ln"a \# 内容自动生成，请勿编辑修改或删除\!\!\!" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a \[ \! \-d \""${PATH_LOCK}"\" \] \&\& \{ mkdir \-p \""${PATH_LOCK}"\"\; chmod 777 \""${PATH_LOCK}"\"\; \} \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a exec "$LOCK_FILE_ID"\<\>\""${LOCK_FILE}"\"\; flock \-x "$LOCK_FILE_ID" \> \/dev\/null 2\>\&1\; \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a ip rule show \| grep \""$IP_RULE_PRIO_OPENVPN"\:\" \| sed \-e \"s\/\^\\\("$IP_RULE_PRIO_OPENVPN"\\\)\:\.\*\$\/ip rule del prio \\\1\/g\" \| awk \'\{system\(\$0 \" > \/dev\/null 2>&1\"\)\}\' \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a if \[ \-n \"\$\( ip route \| grep nexthop \| sed \-n 1p \)\" \]\; then \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a \\\tlz_route_list\=\$\( ip route \| grep \-Ev \"default\|nexthop\" \) \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a \\\tif \[ \-n \"\$lz_route_list\" \]\; then \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))
	sed -i ""$ln"a \\\t\techo \"\$lz_route_list\" \| sed \-e \"s\/\^\.\*\$\/ip route add \& table "$WAN0"\/g\" \| awk \'\{system\(\$0 \" > \/dev\/null 2>&1\"\)\}\' \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))
	sed -i ""$ln"a \\\t\techo \"\$lz_route_list\" \| sed \-e \"s\/\^\.\*\$\/ip route add \& table "$WAN1"\/g\" \| awk \'\{system\(\$0 \" > \/dev\/null 2>&1\"\)\}\' \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a \\\t\tif [ \-n \"\$( ip route show table "$LZ_IPTV" | grep default )\" ]; then \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	let ln++
	sed -i ""$ln"a \\\t\t\techo \"\$lz_route_list\" \| sed \-e \"s\/\^\.\*\$\/ip route add \& table "$LZ_IPTV"\/g\" \| awk \'\{system\(\$0 \" \> \/dev\/null 2\>\&1\"\)\}\' \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	let ln++
	sed -i ""$ln"a \\\t\tfi \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	let ln++

	sed -i ""$ln"a \\\tfi \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a fi \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a ip route flush cache \> \/dev\/null 2\>\&1 \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	ln=$(( $ln + 1 ))

	sed -i ""$ln"a echo \$(date) [\$\$]\: Running LZ SAR openvpn-event "$LZ_VERSION" \>\> \/tmp\/syslog\.log \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
	let ln++

	sed -i ""$ln"a flock \-u "$LOCK_FILE_ID" \> \/dev\/null 2\>\&1 \# By LZ" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}

	chmod +x ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME}
}

## 创建openvpn-event事件触发文件并添加路由规则项
lz_create_openvpn_event_command() {
	if [ ! -d ${PATH_BOOTLOADER} ]; then
		mkdir -p ${PATH_BOOTLOADER}
	fi

	if [ ! -f ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} ]; then
		cat > ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} <<EOF
#!/bin/sh
EOF
	fi

	## 事件处理脚本内容为空
	local local_write_scripts=$( grep "grep -E \"tap\|tun\"" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} )
	if [ -z "$local_write_scripts" ]; then
		## 清除openvpn-event中命令行
		lz_clear_openvpn_event_command

		## 填写openvpn-event事件触发文件内容并添加路由规则项脚本
		lz_add_openvpn_event_scripts
	else
		## 版本改变
		local_write_scripts=$( grep "# ${OPENVPN_EVENT_NAME} $LZ_VERSION" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} )
		if [ -z "$local_write_scripts" ]; then
			## 清除openvpn-event中命令行
			lz_clear_openvpn_event_command

			## 填写openvpn-event事件触发文件内容并添加路由规则项脚本
			lz_add_openvpn_event_scripts
		else
			## 优先级发生改变
			local_write_scripts=$( grep "$IP_RULE_PRIO_OPENVPN:" ${PATH_BOOTLOADER}/${OPENVPN_EVENT_NAME} )
			if [ -z "$local_write_scripts" ]; then
				## 清除openvpn-event中命令行
				lz_clear_openvpn_event_command

				## 填写openvpn-event事件触发文件内容并添加路由规则项脚本
				lz_add_openvpn_event_scripts
			fi
		fi
	fi
}

## OpenVPN服务支持（TAP及TUN接口类型）
lz_openvpn_support() {
	## 判断是否是双线路接入
	[ -z "$( ip route | grep nexthop | sed -n 1p )" ] && return

	## 判断是否有LZ分流服务运行
	## 返回值：
	##     1--有
	##     0--无
	lz_is_lz_rule_running
	[ "$?" = "1" ] && return

	## 清理OpenVPN服务子网出口规则
	lz_clear_openvpn_rule

	local local_ov_no=0

	local local_route_list=$( ip route | grep -Ev 'default|nexthop' )
	[ -n "$local_route_list" ] && {
		echo "$local_route_list" | sed -e "s/^.*$/ip route add & table "$WAN0"/g" | \
			awk '{system($0 " > \/dev\/null 2>\&1")}'
		echo "$local_route_list" | sed -e "s/^.*$/ip route add & table "$WAN1"/g" | \
			awk '{system($0 " > \/dev\/null 2>\&1")}'

		ip route flush cache > /dev/null 2>&1

		for local_tun_list in $( echo "$local_route_list" | grep -E "tap|tun" | grep "link" | awk '{print $1":"$3}' )
		do
			local_ov_no=$(( $local_ov_no + 1 ))
			local local_openvpn_subnet=$( echo "$local_tun_list" | awk -F ":" '{print $1}' )
			local local_tun_number=$( echo "$local_tun_list" | awk -F ":" '{print $2}' )
			echo $(date) [$$]: LZ openvpn_server_$local_ov_no = $echo $local_tun_number $local_openvpn_subnet >> /tmp/syslog.log
			echo $(date) [$$]: "OpenVPN Server $local_ov_no: $local_tun_number $local_openvpn_subnet"
		done
	}

	if [ $local_ov_no -gt 0 ]; then
		echo $(date) [$$]: -------- LZ IPTV $LZ_VERSION OpenVPN Server Go! ---- >> /tmp/syslog.log
	fi

	## 创建openvpn-event事件触发文件并添加路由规则项
	lz_create_openvpn_event_command
}

main() {
	## 项目文件及目录管理
	lz_optimize_file_directory_structure

	if [ "$is_lz_rule_iptv" = "0" ]; then
		## 清除系统策略路由库中已有IPTV规则
		lz_del_iptv_rule

		## 清空系统中已有IPTV路由表
		lz_clear_iptv_route

		## 恢复系统原有IPTV服务
		## 输入项：
		##     $1--是否显示执行结果（1--显示；其它符号--禁止显示）
		## 返回值：无
		show_result=stop
		[ "$1" = "stop" ] && show_result=1
		lz_restore_sys_iptv_services "$show_result"
		unset show_result
	fi

	vconfig set_name_type DEV_PLUS_VID_NO_PAD

	## 关闭路由器内全部对外VLAN接口
	## 输入项：
	##     $1--路由器内网桥标识
	##     0--成功
	##     1--失败
	##     255--参数内容为空
	lz_close_all_route_vlan_if "br0"
	local reval="$?"

	if [ "$1" != "stop" ]; then
		## 初始化单臂路由VLAN参数
		## 输入项：
		##     全局变量
		## 返回值：
		##     0--成功
		##     1--失败
		lz_Initialize_vlan_parameters
		if [ "$?" = "1" ]; then
			echo $(date) [$$]: "VLAN parameter setting error !!!"
			echo $(date) [$$]: "VLAN parameter setting error !!!" >> /tmp/syslog.log
			return 1
		fi

		## 校验IPTV连接方式，错误则退出
		if [ $iptv_stb_get_ip_mode -lt 1 -o $iptv_stb_get_ip_mode -gt 3 ]; then
			echo $(date) [$$]: "iptv_stb_get_ip_mode parameter setting error !!!"
			echo $(date) [$$]: "iptv_stb_get_ip_mode parameter setting error !!!" >> /tmp/syslog.log
			return 1
		fi

		## 校验IPTV机顶盒访问IPTV网络方式，错误则退出
		if [ $iptv_stb_access_mode -lt 1 -o $iptv_stb_access_mode -gt 2 ]; then
			echo $(date) [$$]: "iptv_stb_access_mode parameter setting error !!!"
			echo $(date) [$$]: "iptv_stb_access_mode parameter setting error !!!" >> /tmp/syslog.log
			return 1
		fi

		## 校验hnd平台机型核心网桥组播控制方式，错误则退出
		if [ $hnd_br0_bcmmcast_mode -lt 0 -o $hnd_br0_bcmmcast_mode -gt 2 ]; then
			echo $(date) [$$]: "hnd_br0_bcmmcast_mode parameter setting error !!!"
			echo $(date) [$$]: "hnd_br0_bcmmcast_mode parameter setting error !!!" >> /tmp/syslog.log
			return 1
		fi

		## 获取路由器内的核心网桥
		local bridge_name="$( brctl show | grep -o br0 | sed -n 1p )"
		if [ -z "$bridge_name" ]; then
			echo $(date) [$$]: "Unable to get bridge br0 in router to start SAR service."
			echo $(date) [$$]: "Unable to get bridge br0 in router to start SAR service." >> /tmp/syslog.log
			return 1
		fi

		## 获取WAN口接口设备标识
		local wan0_ifname="$( nvram get wan0_ifname | grep -Eo 'vlan[0-9]*|eth[0-9]*' | sed -n 1p )"
		local wan1_ifname="$( nvram get wan1_ifname | grep -Eo 'vlan[0-9]*|eth[0-9]*' | sed -n 1p )"
		if [ -z "$wan0_ifname" -a -z "$wan1_ifname" ]; then
			echo $(date) [$$]: "Unable to get the correct interface to start the SAR service."
			echo $(date) [$$]: "Unable to get the correct interface to start the SAR service." >> /tmp/syslog.log
			return 1
		fi
	fi

	if [ "$reval" = "1" ]; then
		## 关闭路由器内指定对外VLAN接口
		## 输入项：
		##     $1--WAN口接口设备标识
		##     $2--所接网络VLAN_ID值
		##     $3--路由器内网桥标识
		## 返回值：无
		## 关闭第二WAN口路由器4号本地内网VLAN接口
		lz_close_route_vlan_if "$wan1_ifname" "$wan2_4_vlan_id" "br0"

		## 关闭第二WAN口路由器3号本地内网VLAN接口
		lz_close_route_vlan_if "$wan1_ifname" "$wan2_3_vlan_id" "br0"

		## 关闭第二WAN口路由器2号本地内网VLAN接口
		lz_close_route_vlan_if "$wan1_ifname" "$wan2_2_vlan_id" "br0"

		## 关闭第二WAN口路由器1号本地内网VLAN接口
		lz_close_route_vlan_if "$wan1_ifname" "$wan2_1_vlan_id" "br0"

		## 关闭第一WAN口路由器4号本地内网VLAN接口
		lz_close_route_vlan_if "$wan0_ifname" "$wan1_4_vlan_id" "br0"

		## 关闭第一WAN口路由器3号本地内网VLAN接口
		lz_close_route_vlan_if "$wan0_ifname" "$wan1_3_vlan_id" "br0"

		## 关闭第一WAN口路由器2号本地内网VLAN接口
		lz_close_route_vlan_if "$wan0_ifname" "$wan1_2_vlan_id" "br0"

		## 关闭第一WAN口路由器1号本地内网VLAN接口
		lz_close_route_vlan_if "$wan0_ifname" "$wan1_1_vlan_id" "br0"
	fi

	## 退出
	if [ "$1" = "stop" ]; then
		## 清理OpenVPN服务子网出口规则
		lz_clear_openvpn_rule

		## 清除openvpn-event中命令行
		lz_clear_openvpn_event_command

		## 清除firewall-start中脚本引导项
		lz_clear_firewall_start_command

		if [ "$is_lz_rule_iptv" = "0" ]; then
			## 恢复系统负载均衡分流策略规则为系统初始的优先级状态
			## 处理系统负载均衡分流策略规则
			## 输入项：
			##     $1--规则优先级（150--梅林原始；$IP_RULE_PRIO + 1--脚本定义）
			##     全局常量
			## 返回值：无
			lz_sys_load_balance_control "150"
		fi

		echo $(date) [$$]: "LZ SAR service support provided by the script has finished."
		echo $(date) [$$]: "LZ SAR service support provided by the script has finished." >> /tmp/syslog.log
		return 0
	fi

	## 创建firewall-start启动文件并添加脚本引导项
	lz_create_firewall_start_command

	## 设置并启动路由器VLAN接口
	## 输入项：
	##     $1--WAN口接口设备标识
	##     $2--所接网络VLAN_ID值
	##     $3--路由器内网桥标识
	## 返回值：无
	## 设置并启动路由器第一WAN口1号本地内网VLAN接口
	lz_setup_route_vlan_if "$wan0_ifname" "$wan1_1_vlan_id" "$bridge_name"

	## 设置并启动路由器第一WAN口2号本地内网VLAN接口
	lz_setup_route_vlan_if "$wan0_ifname" "$wan1_2_vlan_id" "$bridge_name"

	## 设置并启动路由器第一WAN口3号本地内网VLAN接口
	lz_setup_route_vlan_if "$wan0_ifname" "$wan1_3_vlan_id" "$bridge_name"

	## 设置并启动路由器第一WAN口4号本地内网VLAN接口
	lz_setup_route_vlan_if "$wan0_ifname" "$wan1_4_vlan_id" "$bridge_name"

	## 设置并启动路由器第二WAN口1号本地内网VLAN接口
	lz_setup_route_vlan_if "$wan1_ifname" "$wan2_1_vlan_id" "$bridge_name"

	## 设置并启动路由器第二WAN口2号本地内网VLAN接口
	lz_setup_route_vlan_if "$wan1_ifname" "$wan2_2_vlan_id" "$bridge_name"

	## 设置并启动路由器第二WAN口3号本地内网VLAN接口
	lz_setup_route_vlan_if "$wan1_ifname" "$wan2_3_vlan_id" "$bridge_name"

	## 设置并启动路由器第二WAN口4号本地内网VLAN接口
	lz_setup_route_vlan_if "$wan1_ifname" "$wan2_4_vlan_id" "$bridge_name"

	## 显示输出VLAN接口状态信息
	## 输入项：
	##     全局变量
	## 返回值：无
	lz_display_output_vlan_interface_status_infor

	if [ "$is_lz_rule_iptv" = "0" ]; then
		## 处理系统负载均衡分流策略规则
		## 输入项：
		##     $1--规则优先级（150--梅林原始；$IP_RULE_PRIO + 1--脚本定义）
		##     全局常量
		## 返回值：无
		lz_sys_load_balance_control "$(( $IP_RULE_PRIO + 1 ))"

		## IPTV服务支持
		## 输入项：
		##     $1--第一WAN口接口设备标识
		##     $2--第二WAN口接口设备标识
		##     全局变量
		## 返回值：无
		lz_iptv_support "$wan0_ifname" "$wan1_ifname"
	fi

	## OpenVPN服务支持（TAP及TUN接口类型）
	lz_openvpn_support

	return 0
}

echo $(date) [$$]:
echo $(date) [$$]: LZ SAR $LZ_VERSION script commands start......
echo $(date) [$$]: By LZ \(larsonzhang@gmail.com\)
echo $(date) [$$]: -------- LZ SAR $LZ_VERSION come here! ------------- >> /tmp/syslog.log
if [ "$1" != "stop" ]; then
	echo $(date) [$$]: "Start the SAR service......"
	echo $(date) [$$]: "Start the SAR service......" >> /tmp/syslog.log
else
	echo $(date) [$$]: "Stop the SAR service......"
	echo $(date) [$$]: "Stop the SAR service......" >> /tmp/syslog.log
fi

## 判断是否有LZ分流IPTV服务运行
## 返回值：
##     1--有
##     0--无
lz_is_lz_rule_iptv_running
is_lz_rule_iptv="$?"

main "$1"

if [ "$?" = "1" ]; then
	## 清除firewall-start中脚本引导项
	lz_clear_firewall_start_command
	## 恢复系统负载均衡分流策略规则为系统初始的优先级状态
	[ "$is_lz_rule_iptv" = "0" ] && lz_sys_load_balance_control "150"
fi

## 清除IPTV机顶盒内网IP地址列表临时文件
if [ -f /tmp/lz_iptv_box_ip.lst ]; then
	rm /tmp/lz_iptv_box_ip.lst > /dev/null 2>&1
fi

echo $(date) [$$]: LZ SAR $LZ_VERSION script commands executed!
echo $(date) [$$]: -------- LZ SAR $LZ_VERSION executed! -------------- >> /tmp/syslog.log
echo $(date) [$$]:

## 解除文件同步锁
flock -u "$LOCK_FILE_ID" > /dev/null 2>&1
