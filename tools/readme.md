1、本工具用于HVB格式的镜像签名

 - hvbtool.py  镜像签名脚本，是签名工具的执行脚本

 

2、使用方法

 - hash类镜像签名

   ./hvbtool.py make_hash_footer --image xxx.img                             //待签名镜像

   ​                                                        --partition xxx                                 //分区名

   ​                                                        --partition_size 31457280             //分区大小

   ​                                                        --salt xxxxxxxxxxxxxxxx                //盐值

   ​                                                        --pubkey xxx_pub.pem                 //公钥key

   ​                                                        --privkey xxx_priv.pem                  //私钥key

   ​                                                        --algorithm SHA256_RSA2048     //签名算法

   ​                                                        --rollback_index                             //防回滚号

   ​                                                        --rollback_location                         //防回滚号存放位置

   ​                                                        --output xxx.img                            //签名后镜像

   e.g.    ./hvbtool.py make_hash_footer --image boot.img --partition boot --partition_size 31457280 --salt 9f3a79b7f2bad5adb086bcb8cf37f991733f2696 --pubkey boot_pub.pem --privkey boot_priv.pem --algorithm SHA256_RSA2048 --rollback_index 0 --rollback_location 1 --output ./signed_boot.img

 

 - hashtree类镜像签名

   ./hvbtool.py make_hashtree_footer --image xxx.img                       //待签名镜像

   ​                                                        --partition xxx                                  //分区名

   ​                                                        --partition_size 3724541952         //分区大小

   ​                                                        --salt xxxxxxxxxxxxxxxx                //盐值

   ​                                                        --pubkey xxx_pub.pem                 //公钥key

   ​                                                        --privkey xxx_priv.pem                  //私钥key

   ​                                                        --algorithm SHA256_RSA2048     //签名算法

   ​                                                        --rollback_index                             //防回滚号

   ​                                                        --rollback_location                         //防回滚号存放位置

   ​                                                        --output xxx.img                            //签名后镜像

   e.g.    ./hvbtool.py make_hashtree_footer --image system.img --partition system --partition_size 3724541952 --salt 9f3a79b7f2bad5adb086bcb8cf37f991733f2696 --pubkey system_pub.pem --privkey system_priv.pem --algorithm SHA256_RSA2048  --rollback_index 0 --rollback_location 1 --output ./signed_system.img

 

 - 制作rvt镜像

   ./hvbtool.py mak_rvt_image --partition rvt                                       //rvt分区

   ​                                                  --partition_size 4194304                    //分区大小

   ​                                                  --salt xxxxxxxxxxxxxxxxx                   //盐值

   ​                                                  --pubkey xxx_pub.pem                      //公钥key

   ​                                                  --privkey xxx_priv.pem                       //私钥key

   ​                                                  --algorithm SHA256_RSA2048           //签名算法

   ​                                                  --rollback_index                                   //防回滚号

   ​                                                  --rollback_location                              //防回滚号存放位置

   ​                                                  --chain_partition xxx:xxx_pubkey.pem

   ​                                                                                                                 //校验链路的分区：公钥，可以有多个，

   ​                                                                                                                 //每个chain_partition表示一个分区

   ​                                                  --output rvt.img                                   //输出rvt镜像

 

   e.g.    ./hvbtool.py make_rvt_image --salt 9f3a79b7f2bad5adb086bcb8cf37f991733f2696 --pubkey test_pub.pem --privkey test_priv.pem --partition rvt --partition_size 4194304 --algorithm SHA256_RSA2048 --rollback_index 0 --rollback_location 1 --chain_partition boot:boot_pub.pem --chain_partition ramdisk:ramdisk_pub.pem --chain_partition eng_vendor:eng_vendor_pub.pem  --chain_partition eng_system:eng_system_pub.pem --output ./rvt.img

 

 - 解析hvb镜像

   ./hvbtool.py parse_image --image xxx.img                  //待解析的hvb签名镜像

   e.g.    ./hvbtool.py parse_image --image odm.img

 

 - 擦除签名镜像的footer及签名内容

   ./hvbtool.py erase_image --image xxx.img                //待擦除的hvb签名镜像

   e.g.    ./hvbtool.py erase_image --image odm.img

3、注意事项

 - 需要python3. 0.0以上的版本
 - 待签名镜像可以放在任意目录，执行脚本时，传入绝对路径或相对路径皆可
 - 执行hvbtool.py脚本时，各参数间用空格隔开，不能换行
