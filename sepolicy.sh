./sepolicy-inject -s vold -t kernel -c security -p load_policy -P sepolicy -o sepolicy
./sepolicy-inject -s vold -t kernel -c security -p setenforce -P sepolicy -o sepolicy
./sepolicy-inject -s vold -t selinuxfs -c file -p write -P sepolicy -o sepolicy
#./sepolicy-inject -s vold -t shell_data_file -c dir -p search -P sepolicy -o sepolicy
#./sepolicy-inject -s vold -t shell_data_file -c file -p read -P sepolicy -o sepolicy
#./sepolicy-inject -s vold -t shell_data_file -c file -p getattr -P sepolicy -o sepolicy
#./sepolicy-inject -s vold -t shell_data_file -c file -p open -P sepolicy -o sepolicy
#./sepolicy-inject -s vold -t system_file -c filesystem -p mount -P sepolicy -o sepolicy
#./sepolicy-inject -s vold -t system_file -c filesystem -p unmount -P sepolicy -o sepolicy
#./sepolicy-inject -s vold -t system_file -c filesystem -p remount -P sepolicy -o sepolicy


#cp /sepolicy /data/local/tmp/sepolicy_modify
#./sepolicy-inject -s vold -t kernel -c security -p load_policy -P sepolicy_modify -o sepolicy_modify
#./sepolicy-inject -s vold -t selinuxfs -c file -p write -P sepolicy_modify -o sepolicy_modify
#./sepolicy-inject -s vold -t shell_data_file -c dir -p search -P sepolicy_modify -o sepolicy_modify
#./sepolicy-inject -s vold -t shell_data_file -c file -p read -P sepolicy_modify -o sepolicy_modify
#./sepolicy-inject -s vold -t shell_data_file -c file -p getattr -P sepolicy_modify -o sepolicy_modify
#./sepolicy-inject -s vold -t shell_data_file -c file -p open -P sepolicy_modify -o sepolicy_modify
#./sepolicy-inject -s vold -t system_file -c filesystem -p mount -P sepolicy_modify -o sepolicy_modify
#./sepolicy-inject -s vold -t system_file -c filesystem -p unmount -P sepolicy_modify -o sepolicy_modify
#./sepolicy-inject -s vold -t system_file -c filesystem -p remount -P sepolicy_modify -o sepolicy_modify
#allow vold kernel:security load_policy;
#allow vold selinuxfs:file write;
#allow vold shell_data_file:dir search;
#allow vold shell_data_file:file { read getattr open };

