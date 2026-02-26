#! /bin/sh

pid=$$
ppid=`cat /proc/$pid/status | grep PPid | cut -d':' -f2`
ppid=${ppid:1}

comm=`cat /proc/$ppid/comm`

result=$(echo $comm | grep "customize_exec")
if [ "$result" == "" ]; then
    echo "father : $comm, customize_cert_proc check failed"
    return 1
fi

var_cfg_ft_word=`echo $2 | tr a-z A-Z | cut -d : -f1 `

if [ "$var_cfg_ft_word" = "FIDNADESKAP" ] || [ "$var_cfg_ft_word" = "FIDNADESKAP2" ]; then
    #如果mnt/jffs2下有待解压的证书文件，就把证书文件解压出来
    if [ -f /mnt/jffs2/fidnadeskapcert.tar.gz ]
    then
        curDir=`pwd`
        cd /mnt/jffs2
        tar -zxvf fidnadeskapcert.tar.gz > /dev/null
        if [ "$var_cfg_ft_word" = "FIDNADESKAP2" ]; then
            cp ./FIDNADESKAP2/* ./
        else
            cp ./FIDNADESKAP/* ./
        fi
        chown cfg_cwmp:service /mnt/jffs2/pub.crt
        chown cfg_cwmp:service /mnt/jffs2/root.crt
        chown cfg_cwmp:service /mnt/jffs2/prvt.key
        rm /mnt/jffs2/fidnadeskapcert.tar.gz -f
        rm -rf /mnt/jffs2/FIDNADESKAP
        rm -rf /mnt/jffs2/FIDNADESKAP2
        cd $curDir
    else
        #如果在FIDNADESKAP定制下，/mnt/jffs2/fidnadeskapcert.tar.gz打包证书不存在，则要提示证书问题，定制不能继续走下去
        echo "ERROR::FIDNADESKAP please check Certificates !!!"
        return 1
    fi

    #下面需要判断多证书定制证书是否缺失
    if [ ! -f /mnt/jffs2/pub.crt ]
    then
        echo "ERROR::FIDNADESKAP please check pub.crt !!! "
        return 1
    fi

    if [ ! -f /mnt/jffs2/root.crt ]
    then
        echo "ERROR::FIDNADESKAP please check root.crt !!! "
        return 1
    fi

    if [ ! -f /mnt/jffs2/prvt.key ]
    then
        echo "ERROR::FIDNADESKAP please check prvt.key !!! "
        return 1
    fi

fi

var_jffs2_calist="/mnt/jffs2/calist"
if [ "$var_cfg_ft_word" = "PLPLAYAP" ]; then
    #如果有待解压的证书文件，就把证书文件解压出来
    if [ -f /var/plplayapcert.tar.gz ]
    then
        if [ ! -d $var_jffs2_calist ];then
            mkdir $var_jffs2_calist
            chown cfg_cwmp:service $var_jffs2_calist
            chmod 755 $var_jffs2_calist
        fi
        tar -zxf /var/plplayapcert.tar.gz -C $var_jffs2_calist
        chown cfg_cwmp:service /mnt/jffs2/calist/CertumCA.crt
        chown cfg_cwmp:service /mnt/jffs2/calist/CertumOrganizationValidationCASHA2.crt
        chown cfg_cwmp:service /mnt/jffs2/calist/CertumTrustedNetworkCA.crt
        rm /var/plplayapcert.tar.gz -f
    else
        #如果在PLPLAYAP定制下，/var/plplayapcert.tar.gz打包证书不存在，则要提示证书问题，定制不能继续走下去
        echo "ERROR::PLPLAYAP please check Certificates !!!"
        return 1
    fi

    #下面需要判断多证书定制证书是否缺失
    if [ ! -f /mnt/jffs2/calist/CertumCA.crt ]
    then
        echo "ERROR::PLPLAYAP please check file CertumCA.crt !!!"
        return 1
    fi

    if [ ! -f /mnt/jffs2/calist/CertumOrganizationValidationCASHA2.crt ]
    then
        echo "ERROR::PLPLAYAP please check CertumOrganizationValidationCASHA2.crt !!! "
        return 1
    fi

    if [ ! -f /mnt/jffs2/calist/CertumTrustedNetworkCA.crt ]
    then
        echo "ERROR::PLPLAYAP please check CertumTrustedNetworkCA.crt !!! "
        return 1
    fi

fi

if [ "$var_cfg_ft_word" = "DESKVDFPTAP" ]; then
    #如果有待解压的证书文件，就把证书文件解压出来
    if [ -f /var/deskvdfptapcert.tar.gz ]
    then
        if [ ! -d $var_jffs2_calist ];then
            mkdir $var_jffs2_calist
            chown cfg_cwmp:service $var_jffs2_calist
            chmod 755 $var_jffs2_calist
        fi
        tar -zxf /var/deskvdfptapcert.tar.gz -C $var_jffs2_calist
        chown cfg_cwmp:service /mnt/jffs2/calist/ -R
        rm /var/deskvdfptapcert.tar.gz -f
    else
        #如果在DESKVDFPTAP定制下，/var/deskvdfptapcert.tar.gz打包证书不存在，则要提示证书问题，定制不能继续走下去
        echo "ERROR::DESKVDFPTAP please check Certificates !!!"
        return 1
    fi
fi

if [ "$var_cfg_ft_word" = "TELMEX" ] || [ "$var_cfg_ft_word" = "TELMEX5G" ] \
   || [ "$var_cfg_ft_word" = "TELMEX5GV" ] || [ "$var_cfg_ft_word" = "TELMEX5GV5" ]; then
    if [ -f /var/customize_cert.tar.gz ]
    then 
        cd /var/
        tar -xvzf customize_cert.tar.gz > /dev/null
        chmod 400 -R /var/customize_cert/
        cp /var/customize_cert/*1_telmex.pem /mnt/jffs2/
        chown 3004:2002 /mnt/jffs2/prvt_1_telmex.pem
        chown 3004:2002 /mnt/jffs2/pub_1_telmex.pem
        chown 3004:2002 /mnt/jffs2/root_1_telmex.pem
    else
        #如果在DESKVDFPTAP定制下，/var/deskvdfptapcert.tar.gz打包证书不存在，则要提示证书问题，定制不能继续走下去
        echo "ERROR::TELMEX please check Certificates !!!"
        return 1
    fi

    #证书文复制后校验文件是否存在
    if [ ! -f /mnt/jffs2/prvt_1_telmex.pem ]
    then
        echo "ERROR::TELMEX please check prvt_1_telmex.pem !!! "
        return 1
    fi

    if [ ! -f /mnt/jffs2/pub_1_telmex.pem ]
    then
        echo "ERROR::TELMEX please check pub_1_telmex.pem !!! "
        return 1
    fi

    if [ ! -f /mnt/jffs2/root_1_telmex.pem ]
    then
        echo "ERROR::TELMEX please check root_1_telmex.pem !!! "
        return 1
    fi
fi

exit 0
