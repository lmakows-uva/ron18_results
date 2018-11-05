R="redis-cli -n 4 "
$R "HMSET" "ACL_TABLE|DATAACL6" "type" "l3v6" "policy_desc" "data_acl6" "ports@Ethernet0,Ethernet4,Ethernet8,Ethernet20,Ethernet28"
