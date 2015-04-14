#!/bin/bash

std_iso="/root/fuel-main-redhat/build/artifacts/fuel-6.0.1.iso"
tmp="/mnt/iso2/additional_components"
ctm_iso_name="custom.iso"
stf_loc="/mnt/stuff"

#Customization of iso

#umount old mounts and delete old xources

#for i in `mount | grep iso | grep "/mnt/iso" | awk '{print $1}'` ; 
#do
#  umount -l $i ; 
#done
rm -rf $tmp
rm -rf /mnt/$ctm_iso_name
rm -rf $stf_loc

  
#mount new iso
echo "mkdir -p /mnt/iso"
mkdir -p /mnt/iso
echo "mount -o loop $std_iso /mnt/iso"
mount -o loop $std_iso /mnt/iso

echo "mkdir -p $tmp"
mkdir -p $tmp

echo "cp -r /mnt/iso/* $tmp"
cp -r /mnt/iso/* $tmp
echo "cp /mnt/iso/.treeinfo $tmp"
cp /mnt/iso/.treeinfo $tmp
echo "cp /mnt/iso/.discinfo $tmp"
cp /mnt/iso/.discinfo $tmp


mkdir -p $stf_loc
git clone https://github.com/andrei4ka/ceph_rbd_inc_backup.git $stf_loc/ceph_rbd_inc_backup
git clone https://github.com/andrei4ka/auto_scaling.git $stf_loc/auto_scaling
git clone https://github.com/sshturm/oss_framework.git $stf_loc/oss_framework
git clone https://github.com/sshturm/isrm.git $stf_loc/isrm
git clone https://github.com/grebennikov/reports.git $stf_loc/reports
git clone https://github.com/noskovao/oss_pull.git $stf_loc/oss_pull

cp -r /mnt/stuff/* $tmp

cd /mnt; mkisofs -r -V "Mirantis Fuel" -p "Mirantis Inc." -J -T -R -b isolinux/isolinux.bin \
  -no-emul-boot -boot-load-size 4 -boot-info-table -x "lost+found" -o ./$ctm_iso_name ./iso2

umount $std_iso

