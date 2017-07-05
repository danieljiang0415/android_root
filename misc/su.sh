#!/system/bin/sh

kr_set_perm() {
    chown $1.$2 $5
    chmod $4 $5
    if [ -f "/system/bin/chcon" ]; then
        chcon $3 $5
    fi
}

SOURCE_PATH=/sbin
HIGHT_PROI_PATH=/system/xbin
RUN_ROOT=/dev/kingroot
XBIN_RUN_PATH=/dev/kingroot/xbin_bind
BIN_RUN_PATH=/dev/kingroot/bin_bind

# patch 1
if [ -x $HIGHT_PROI_PATH/supolicy ]; then
    $HIGHT_PROI_PATH/supolicy --live
else
    $SOURCE_PATH/supolicy --live
fi
chmod 00755 /sbin
chown 0.2000 /sbin

# patch 2
if [ -x $HIGHT_PROI_PATH/krdem ]; then
    $HIGHT_PROI_PATH/krdem kingroot-dev 100002
else
    $SOURCE_PATH/krdem kingroot-dev 100002
fi


run_bind() {
	/system/bin/mount -o bind $1 $2
	if [ $? != 0 ]; then
		/sbin/krdem kingroot-dev 23 -o bind $1 $2
		if [ $? != 0 ]; then
			/system/xbin/krdem kingroot-dev 23 -o bind $1 $2
		fi
	fi
}

setup_kusud() {
    # root dir
    mkdir -p $RUN_ROOT
    kr_set_perm 0 0 u:object_r:system_file:s0 00755 $RUN_ROOT
    
    # xbin_bind
    cp -f -a /system/xbin $XBIN_RUN_PATH

    # ku.sud
    cp $SOURCE_PATH/ku.sud $XBIN_RUN_PATH/ku.sud
    ln -s $XBIN_RUN_PATH/ku.sud $XBIN_RUN_PATH/su
    kr_set_perm 0 0 u:object_r:system_file:s0 00755 $XBIN_RUN_PATH/ku.sud
    kr_set_perm 0 0 u:object_r:system_file:s0 00755 $XBIN_RUN_PATH/su

    # bind
    run_bind $XBIN_RUN_PATH /system/xbin
}

setup_mount() {
    cat > $RUN_ROOT/mount <<-EOF
#!/system/bin/sh

((0))
EOF
    # bin_bind
    cp -f -a /system/bin $BIN_RUN_PATH
    
    # replace mount
    rm $BIN_RUN_PATH/mount
    ln -s $RUN_ROOT/mount $BIN_RUN_PATH/mount
    kr_set_perm 0 0 u:object_r:system_file:s0 00755 $RUN_ROOT/mount
    kr_set_perm 0 0 u:object_r:system_file:s0 00755 $BIN_RUN_PATH/mount

    # bind
    run_bind -o bind $BIN_RUN_PATH /system/bin
}

if [ -x $HIGHT_PROI_PATH/ku.sud ]; then
    $HIGHT_PROI_PATH/ku.sud -d
else
    setup_kusud
    #setup_mount
    $XBIN_RUN_PATH/ku.sud -d
fi

/system/etc/kds --global-daemon 4

